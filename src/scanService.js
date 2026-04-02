const { AppError } = require("./errors");

const SCAN_CACHE_TTL_MS = {
  url: 10 * 60 * 1000,
  email: 10 * 60 * 1000
};
const scanCache = new Map();
const inFlightScans = new Map();

function createScanService(config) {
  async function fetchJson(url, options = {}) {
    let response;

    try {
      response = await fetch(url, options);
    } catch (error) {
      throw new AppError(502, "Unable to connect. Check your internet connection.");
    }

    if (response.status === 204 || response.status === 429) {
      throw new AppError(429, "Rate limit reached. Try again in 1 minute.");
    }

    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json")
      ? await response.json().catch(() => ({}))
      : await response.text().catch(() => "");

    if (!response.ok) {
      const message =
        typeof payload === "object"
          ? payload?.error?.message || payload?.message || "Upstream API request failed."
          : String(payload || "Upstream API request failed.");
      throw new AppError(response.status, message);
    }

    return payload;
  }

  function vtHeaders() {
    if (!config.virusTotalApiKey) {
      throw new AppError(
        503,
        "VirusTotal API key is missing. Add VIRUSTOTAL_API_KEY to your .env file."
      );
    }

    return {
      "x-apikey": config.virusTotalApiKey
    };
  }

  async function analyzeUrl(targetUrl) {
    const cachedResult = await withCache(`url:${targetUrl}`, SCAN_CACHE_TTL_MS.url, async () => {
      const submitResponse = await fetchJson("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
          ...vtHeaders(),
          "content-type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({ url: targetUrl }).toString()
      });

      const analysisId = submitResponse?.data?.id;
      if (!analysisId) {
        throw new AppError(502, "VirusTotal did not return an analysis identifier.");
      }

      let analysisPayload = null;
      for (let attempt = 0; attempt < 5; attempt += 1) {
        if (attempt > 0) {
          await delay(1200);
        }

        analysisPayload = await fetchJson(
          `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
          { headers: vtHeaders() }
        );

        if (analysisPayload?.data?.attributes?.status === "completed") {
          break;
        }
      }

      const attributes = analysisPayload?.data?.attributes || {};
      const stats = attributes.stats || {};
      const detections = Object.entries(attributes.results || {})
        .map(([vendor, result]) => {
          const category = result?.category || "";
          return {
            vendor,
            category,
            result: result?.result || category || "no verdict",
            detected: category === "malicious" || category === "suspicious",
            method: result?.method || "unknown"
          };
        })
        .sort((left, right) => {
          if (Number(right.detected) !== Number(left.detected)) {
            return Number(right.detected) - Number(left.detected);
          }
          return left.vendor.localeCompare(right.vendor);
        });

      const malicious = Number(stats.malicious || 0);
      const suspicious = Number(stats.suspicious || 0);
      const harmless = Number(stats.harmless || 0);
      const undetected = Number(stats.undetected || 0);
      const positives = malicious + suspicious;
      const total = malicious + suspicious + harmless + undetected || detections.length;
      const threatScore = clamp(total ? Math.round((positives / total) * 100) : 0, 0, 100);
      const status = attributes.status === "completed" ? "completed" : "pending";
      const threatLevel = status === "pending" ? "suspicious" : severityFromScore(threatScore);
      const topFindings = detections
        .filter((item) => item.detected)
        .slice(0, 5)
        .map((item) => `${item.vendor}: ${item.result}`);

      return {
        type: "url",
        target: targetUrl,
        status,
        positives,
        total,
        threatScore,
        threatLevel,
        stats: {
          malicious,
          suspicious,
          harmless,
          undetected
        },
        detections,
        highlights: topFindings,
        summary:
          status === "pending"
            ? "VirusTotal accepted the URL and is still processing the analysis."
            : positives > 0
              ? `${positives} of ${total} vendors flagged this URL.`
              : `No vendor flagged this URL out of ${total} checks.`
      };
    });

    return {
      ...cachedResult,
      scannedAt: new Date().toISOString()
    };
  }

  async function analyzeEmail(senderEmail) {
    const cachedResult = await withCache(
      `email:${senderEmail}`,
      SCAN_CACHE_TTL_MS.email,
      async () => {
        const fallbackDomain = senderEmail.split("@")[1] || "";
        const hasAbstractKey = Boolean(config.abstractApiKey);
        const [disifyResponse, abstractResponse] = await Promise.allSettled([
          checkDisify(fetchJson, senderEmail),
          validateWithAbstract(fetchJson, config.abstractApiKey, senderEmail)
        ]);
        const hasDisifyResult = disifyResponse.status === "fulfilled";
        const hasAbstractResult =
          abstractResponse.status === "fulfilled" && Boolean(abstractResponse.value);

        const disifyResult =
          hasDisifyResult
            ? disifyResponse.value
            : {
                domain: fallbackDomain,
                disposable: false,
                dns: true,
                format: true
              };
        const abstractResult =
          abstractResponse.status === "fulfilled" ? abstractResponse.value : null;
        const heuristicResult = computeEmailHeuristics(senderEmail);
        const flags = [];
        let trustScore = 100;
        let summary = "No strong phishing indicators were found for this sender address.";

        if (!hasDisifyResult) {
          flags.push("Disify checks are temporarily unavailable, so sender validation is using other signals.");
        }

        if (abstractResponse.status === "rejected") {
          flags.push(
            "Abstract deliverability checks are temporarily unavailable, so the result is based on the remaining checks."
          );
        } else if (!hasAbstractKey) {
          flags.push(
            "Abstract deliverability checks are unavailable until ABSTRACT_API_KEY is configured."
          );
        }

        if (!disifyResult.format) {
          flags.push("Email format is invalid.");
          trustScore -= 35;
        }

        if (!disifyResult.dns) {
          flags.push("Sender domain has no healthy DNS response.");
          trustScore -= 25;
        }

        if (disifyResult.disposable) {
          flags.push("Disposable inbox provider detected.");
          trustScore -= 55;
        }

        if (abstractResult) {
          if (!abstractResult.isValidFormat) {
            flags.push("Abstract API marked the address format as invalid.");
            trustScore -= 40;
          }

          if (abstractResult.isDisposableEmail) {
            flags.push("Abstract API marked the address as disposable.");
            trustScore -= 35;
          }

          if (abstractResult.deliverability === "UNDELIVERABLE") {
            flags.push("Mailbox is marked undeliverable.");
            trustScore -= 35;
          } else if (abstractResult.deliverability === "RISKY") {
            flags.push("Mailbox deliverability is risky.");
            trustScore -= 18;
          }

          if (!Number.isNaN(abstractResult.qualityScore)) {
            trustScore = Math.round((trustScore + abstractResult.qualityScore * 100) / 2);
          }
        }

        for (const signal of heuristicResult.signals) {
          flags.push(signal);
        }
        trustScore -= heuristicResult.penalty;

        trustScore = clamp(trustScore, 0, 100);
        const threatLevel = trustToThreatLevel(trustScore);
        const disposable = disifyResult.disposable || Boolean(abstractResult?.isDisposableEmail);
        const providerChecksUnavailable = !hasDisifyResult || !hasAbstractResult;

        if (threatLevel === "dangerous") {
          summary = "The sender address shows multiple phishing indicators.";
        } else if (threatLevel === "suspicious") {
          summary = "The sender address needs extra verification before you trust it.";
        } else if (!hasDisifyResult && !hasAbstractResult) {
          summary =
            "Live email validation services are limited right now, so this result uses local sender heuristics only.";
        } else if (providerChecksUnavailable) {
          summary =
            "No strong phishing indicators were found, but some live validation checks are currently unavailable.";
        }

        return {
          type: "email",
          target: senderEmail,
          domain: disifyResult.domain,
          trustScore,
          threatLevel,
          disposable,
          flags,
          summary,
          checks: {
            disify: disifyResult,
            abstract: abstractResult
          }
        };
      }
    );

    return {
      ...cachedResult,
      scannedAt: new Date().toISOString()
    };
  }

  async function analyzeCombined(url, email) {
    const [urlResult, emailResult] = await Promise.all([analyzeUrl(url), analyzeEmail(email)]);
    const overallThreatLevel = compareThreatLevels(urlResult.threatLevel, emailResult.threatLevel);
    const overallThreatScore = Math.max(urlResult.threatScore, 100 - emailResult.trustScore);

    return {
      type: "combined",
      scannedAt: new Date().toISOString(),
      threatLevel: overallThreatLevel,
      threatScore: overallThreatScore,
      summary: `Combined scan completed for ${emailResult.domain} and ${new URL(url).hostname}.`,
      url: urlResult,
      email: emailResult
    };
  }

  return {
    analyzeUrl,
    analyzeEmail,
    analyzeCombined
  };
}

async function checkDisify(fetchJson, email) {
  const payload = await fetchJson(`https://api.disify.com/check/${encodeURIComponent(email)}`);
  return {
    domain: payload?.domain || email.split("@")[1],
    disposable: Boolean(payload?.disposable),
    dns: payload?.dns !== false,
    format: payload?.format !== false
  };
}

async function validateWithAbstract(fetchJson, abstractApiKey, email) {
  if (!abstractApiKey) {
    return null;
  }

  const params = new URLSearchParams({
    api_key: abstractApiKey,
    email
  });
  const payload = await fetchJson(`https://emailvalidation.abstractapi.com/v1/?${params.toString()}`);

  return {
    deliverability: payload?.deliverability || "UNKNOWN",
    qualityScore:
      typeof payload?.quality_score === "number"
        ? payload.quality_score
        : Number(payload?.quality_score || NaN),
    isValidFormat: payload?.is_valid_format?.value !== false,
    isDisposableEmail: payload?.is_disposable_email?.value === true
  };
}

function computeEmailHeuristics(email) {
  const [localPart = "", domain = ""] = email.split("@");
  const signals = [];
  let penalty = 0;

  if (/(verify|billing|security|support|payroll|admin|invoice)/i.test(localPart)) {
    signals.push("Sender username uses a high-risk impersonation keyword.");
    penalty += 10;
  }

  if ((localPart.match(/\d/g) || []).length >= 4) {
    signals.push("Sender username contains multiple digits, which is common in throwaway aliases.");
    penalty += 8;
  }

  if (domain.startsWith("xn--")) {
    signals.push("Sender domain uses punycode and should be inspected for lookalike risk.");
    penalty += 20;
  }

  if ((domain.match(/-/g) || []).length >= 3) {
    signals.push("Sender domain contains several hyphens, which can indicate a fabricated brand domain.");
    penalty += 8;
  }

  return { signals, penalty };
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function severityFromScore(score) {
  if (score >= 70) {
    return "dangerous";
  }
  if (score >= 30) {
    return "suspicious";
  }
  return "safe";
}

function trustToThreatLevel(score) {
  if (score < 40) {
    return "dangerous";
  }
  if (score < 70) {
    return "suspicious";
  }
  return "safe";
}

function compareThreatLevels(left, right) {
  const rank = { safe: 1, suspicious: 2, dangerous: 3 };
  return rank[left] >= rank[right] ? left : right;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function clonePayload(payload) {
  if (typeof structuredClone === "function") {
    return structuredClone(payload);
  }

  return JSON.parse(JSON.stringify(payload));
}

function pruneExpiredEntries(store) {
  const now = Date.now();

  for (const [key, entry] of store.entries()) {
    if (entry.expiresAt <= now) {
      store.delete(key);
    }
  }
}

async function withCache(cacheKey, ttlMs, resolver) {
  pruneExpiredEntries(scanCache);

  const cachedEntry = scanCache.get(cacheKey);
  if (cachedEntry && cachedEntry.expiresAt > Date.now()) {
    return clonePayload(cachedEntry.value);
  }

  if (inFlightScans.has(cacheKey)) {
    return clonePayload(await inFlightScans.get(cacheKey));
  }

  const task = (async () => {
    const value = await resolver();
    scanCache.set(cacheKey, {
      value,
      expiresAt: Date.now() + ttlMs
    });
    return value;
  })();

  inFlightScans.set(cacheKey, task);

  try {
    return clonePayload(await task);
  } finally {
    inFlightScans.delete(cacheKey);
  }
}

module.exports = {
  createScanService
};
