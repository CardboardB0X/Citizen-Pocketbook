import * as http from "node:http";
import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import QRCode from "qrcode";
import { MunicipalAuthority } from "./issuer/authority.js";
import { CitizenPocketbookEngine } from "./pocketbook/pocketbook-engine.js";
import { OfflineVerifierEngine } from "./verifier/verifier-engine.js";
import { CLAIM_FLAGS } from "./common/types.js";
import { applySignedRevocationManifest } from "./revocation/delta-manifest.js";
import { generateSelectiveVoucher, VOUCHER_PURPOSES } from "./crypto/selective-proof.js";
import { exportEncryptedAuditLogs } from "./sync/sync-package.js";
import { AyudaDistributionTracker } from "./verifier/ayuda-tracker.js";
import { fragmentPayloadForOpticalRelay } from "./sync/qr-mesh-relay.js";

const PORT = 3000;
const TANZA_LGU_CODE = 42120000; // Philippine Standard Geographic Code (PSGC) for Tanza, Cavite
const MUNICIPAL_SYNC_KEY = crypto.createHash("sha256").update("tanza-municipal-sync-2026").digest();

// Initialize Core Engines
const authority = new MunicipalAuthority(TANZA_LGU_CODE, "Municipality of Tanza, Cavite");
const verifier = new OfflineVerifierEngine();
verifier.registerTrustedLgu(TANZA_LGU_CODE, authority.getPublicKey());
const ayudaTracker = new AyudaDistributionTracker();

// In-Memory Municipal Registry Store
interface RegisteredCitizen {
  fullName: string;
  birthDate: string;
  barangay: string;
  pseudonym: string;
  citizenIndex: number;
  claimsMask: number;
  rawCredentialBase64: string;
  issuedAt: number;
  status: "ACTIVE" | "REVOKED";
}

const registeredCitizens: RegisteredCitizen[] = [
  {
    fullName: "Juan Bautista dela Cruz",
    birthDate: "1958-06-24",
    barangay: "Barangay Daang Amaya II",
    pseudonym: "e04b82d7a22f4b7da3c59a0f7e812d44",
    citizenIndex: 1001,
    claimsMask: CLAIM_FLAGS.RESIDENT | CLAIM_FLAGS.SENIOR_CITIZEN | CLAIM_FLAGS.INDIGENT_4PS | CLAIM_FLAGS.VOTER_ACTIVE,
    rawCredentialBase64: "",
    issuedAt: Date.now() - 86400000 * 30,
    status: "ACTIVE",
  },
  {
    fullName: "Maria Santos Rodriguez",
    birthDate: "1955-09-14",
    barangay: "Barangay Julugan I",
    pseudonym: "3a91f5e2d14872cbb0924e719aa01823",
    citizenIndex: 1002,
    claimsMask: CLAIM_FLAGS.RESIDENT | CLAIM_FLAGS.SENIOR_CITIZEN | CLAIM_FLAGS.VOTER_ACTIVE,
    rawCredentialBase64: "",
    issuedAt: Date.now() - 86400000 * 15,
    status: "ACTIVE",
  },
  {
    fullName: "Carlos Mendoza Hernandez",
    birthDate: "1984-11-03",
    barangay: "Barangay Amaya II",
    pseudonym: "7f4c1a89b023e4125d98fa632145bc09",
    citizenIndex: 1003,
    claimsMask: CLAIM_FLAGS.RESIDENT | CLAIM_FLAGS.INDIGENT_4PS | CLAIM_FLAGS.SOLO_PARENT | CLAIM_FLAGS.VOTER_ACTIVE,
    rawCredentialBase64: "",
    issuedAt: Date.now() - 86400000 * 5,
    status: "ACTIVE",
  },
  {
    fullName: "Elena Ramos Bautista",
    birthDate: "1992-04-18",
    barangay: "Barangay Bucal",
    pseudonym: "bc418a09f1234d567890abcdef123456",
    citizenIndex: 1004,
    claimsMask: CLAIM_FLAGS.RESIDENT | CLAIM_FLAGS.PWD | CLAIM_FLAGS.VOTER_ACTIVE,
    rawCredentialBase64: "",
    issuedAt: Date.now() - 86400000 * 2,
    status: "ACTIVE",
  },
];

// Issue credentials for all pre-seeded citizens
for (const citizen of registeredCitizens) {
  const cred = authority.issueCredential(citizen.pseudonym, citizen.claimsMask);
  citizen.citizenIndex = cred.citizenIndex;
  citizen.rawCredentialBase64 = cred.base64Url;
}

const pocketbook = new CitizenPocketbookEngine();
const CITIZEN_PIN = "123456";
pocketbook.provision(
  {
    masterCredentialRaw: registeredCitizens[0].rawCredentialBase64,
    deviceSecretHex: crypto.randomBytes(32).toString("hex"),
    profileMetadata: {
      fullName: registeredCitizens[0].fullName,
      birthDate: registeredCitizens[0].birthDate,
      photoHashSha256: crypto.createHash("sha256").update("citizen_photo_tanza").digest("hex"),
      registeredAddress: `${registeredCitizens[0].barangay}, Tanza, Cavite`,
    },
  },
  CITIZEN_PIN
);
pocketbook.unlock(CITIZEN_PIN);

const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host}`);

  // Static File Serving
  if (req.method === "GET") {
    let filePath = "";
    let contentType = "text/html; charset=utf-8";

    if (url.pathname === "/" || url.pathname === "/client") {
      filePath = path.resolve(process.cwd(), "public", "client.html");
    } else if (url.pathname === "/terminal") {
      filePath = path.resolve(process.cwd(), "public", "terminal.html");
    } else if (url.pathname === "/admin") {
      filePath = path.resolve(process.cwd(), "public", "admin.html");
    } else if (url.pathname === "/sync") {
      filePath = path.resolve(process.cwd(), "public", "sync.html");
    } else if (url.pathname === "/manifest.webmanifest") {
      filePath = path.resolve(process.cwd(), "public", "manifest.webmanifest");
      contentType = "application/manifest+json";
    } else if (url.pathname === "/sw.js") {
      filePath = path.resolve(process.cwd(), "public", "sw.js");
      contentType = "application/javascript";
    }

    if (filePath) {
      if (!fs.existsSync(filePath)) {
        res.writeHead(404, { "Content-Type": "text/plain" });
        return res.end("File not found.");
      }
      res.writeHead(200, { "Content-Type": contentType });
      return fs.createReadStream(filePath).pipe(res);
    }
  }

  // API: Get Current Citizen Dynamic QR Presentation
  if (req.method === "GET" && url.pathname === "/api/pocketbook/qr") {
    const presentation = pocketbook.generateDynamicQr();
    QRCode.toDataURL(presentation.qrString, {
      width: 260,
      margin: 1,
      color: { dark: "#000000", light: "#ffffff" },
    }).then((qrDataUrl) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          ...presentation,
          qrDataUrl,
          profile: pocketbook.getProfile(),
          citizenIndex: registeredCitizens[0].citizenIndex,
          isRevoked: authority.revocationRegistry.isRevoked(registeredCitizens[0].citizenIndex),
        })
      );
    }).catch((err) => {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: err.message }));
    });
    return;
  }

  // API: Get Selective Disclosure Sub-Voucher
  if (req.method === "GET" && url.pathname === "/api/pocketbook/voucher") {
    const purposeParam = url.searchParams.get("purpose") || "SENIOR_MEDICINE";
    let claimsMask = CLAIM_FLAGS.SENIOR_CITIZEN;
    let purposeCode: number = VOUCHER_PURPOSES.SENIOR_MEDICINE;
    let claimText = "Senior Citizen (OSCA 20% Privilege)";

    if (purposeParam === "RICE_AYUDA") {
      claimsMask = CLAIM_FLAGS.INDIGENT_4PS;
      purposeCode = VOUCHER_PURPOSES.RICE_AYUDA;
      claimText = "4Ps DSWD Beneficiary (Rice Subsidy)";
    } else if (purposeParam === "FREE_MEDICINE") {
      claimsMask = CLAIM_FLAGS.RESIDENT;
      purposeCode = VOUCHER_PURPOSES.CALAMITY_RELIEF;
      claimText = "Bonafide Resident (Lingap Tanza Health)";
    }

    const voucher = generateSelectiveVoucher(
      TANZA_LGU_CODE,
      registeredCitizens[0].pseudonym,
      claimsMask,
      purposeCode,
      3600, // 1 hour validity
      authority.getPrivateKey()
    );

    QRCode.toDataURL(voucher.base64Url, {
      width: 260,
      margin: 1,
      color: { dark: "#000000", light: "#ffffff" },
    }).then((qrDataUrl) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ voucher, qrDataUrl, disclosedClaimText: claimText }));
    }).catch((err) => {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: err.message }));
    });
    return;
  }

  // API: Export Encrypted Audit Logs for USB Transfer
  if (req.method === "GET" && url.pathname === "/api/sync/export-audit") {
    const records = verifier.auditLedger.getRecords();
    const pkgBuffer = exportEncryptedAuditLogs("TERM-TANZA-001", records, MUNICIPAL_SYNC_KEY);

    res.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": 'attachment; filename="tanza_audit_2026.enc"',
      "Content-Length": pkgBuffer.length,
    });
    return res.end(pkgBuffer);
  }

  // API: Field Verifier Scans & Validates QR
  if (req.method === "POST" && url.pathname === "/api/verifier/scan") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      try {
        const { qrPayload } = JSON.parse(body);
        const startTime = performance.now();
        const result = verifier.verify(qrPayload);
        const durationMs = performance.now() - startTime;

        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: true, result, latencyMs: durationMs }));
      } catch (err: any) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: false, error: err.message, code: err.code }));
      }
    });
    return;
  }

  // API: Disaster Ayuda Operations
  if (req.method === "GET" && url.pathname === "/api/ayuda/events") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify(ayudaTracker.getEvents()));
  }

  if (req.method === "GET" && url.pathname === "/api/ayuda/records") {
    const eventId = url.searchParams.get("eventId") || undefined;
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify(ayudaTracker.getAllClaims(eventId)));
  }

  if (req.method === "POST" && url.pathname === "/api/ayuda/claim") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      try {
        const { citizenPseudonym, citizenIndex, eventId, stationId } = JSON.parse(body);
        const receipt = ayudaTracker.recordClaim(citizenPseudonym, citizenIndex, eventId, stationId);
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: true, receipt }));
      } catch (err: any) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: false, error: err.message }));
      }
    });
    return;
  }

  // API: Optical QR-to-QR Mesh Relay Beaming
  if (req.method === "GET" && url.pathname === "/api/mesh/beam-manifest") {
    const manifest = authority.exportSignedRevocationManifest();
    const frames = fragmentPayloadForOpticalRelay(manifest, 140);

    // Pre-generate QR Data URLs for all optical frames
    Promise.all(
      frames.map((frame) =>
        QRCode.toDataURL(frame.base64Url, {
          width: 280,
          margin: 1,
          color: { dark: "#000000", light: "#ffffff" },
        }).then((qrDataUrl) => ({ ...frame, qrDataUrl }))
      )
    ).then((animatedFrames) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ totalFrames: frames.length, frames: animatedFrames }));
    }).catch((err) => {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: err.message }));
    });
    return;
  }

  // API: Admin Operations
  if (req.method === "GET" && url.pathname === "/api/admin/citizens") {
    const citizensWithStatus = registeredCitizens.map((c) => ({
      ...c,
      isRevoked: authority.revocationRegistry.isRevoked(c.citizenIndex),
    }));
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify(citizensWithStatus));
  }

  if (req.method === "GET" && url.pathname === "/api/admin/stats") {
    let seniorCount = 0;
    let indigentCount = 0;
    let pwdCount = 0;
    let soloParentCount = 0;
    let revokedCount = 0;

    for (const c of registeredCitizens) {
      if (c.claimsMask & CLAIM_FLAGS.SENIOR_CITIZEN) seniorCount++;
      if (c.claimsMask & CLAIM_FLAGS.INDIGENT_4PS) indigentCount++;
      if (c.claimsMask & CLAIM_FLAGS.PWD) pwdCount++;
      if (c.claimsMask & CLAIM_FLAGS.SOLO_PARENT) soloParentCount++;
      if (authority.revocationRegistry.isRevoked(c.citizenIndex)) revokedCount++;
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(
      JSON.stringify({
        totalRegistered: registeredCitizens.length,
        activeCount: registeredCitizens.length - revokedCount,
        revokedCount,
        seniorCount,
        indigentCount,
        pwdCount,
        soloParentCount,
        municipalityName: "Bayan ng Tanza, Lalawigan ng Cavite",
        psgcCode: "042120000",
      })
    );
  }

  if (req.method === "POST" && url.pathname === "/api/admin/enroll") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const { fullName, birthDate, barangay, claimsMask } = JSON.parse(body);
        const pseudonym = crypto.randomBytes(16).toString("hex");

        const cred = authority.issueCredential(pseudonym, claimsMask || CLAIM_FLAGS.RESIDENT);
        const newCitizen: RegisteredCitizen = {
          fullName,
          birthDate,
          barangay,
          pseudonym,
          citizenIndex: cred.citizenIndex,
          claimsMask: claimsMask || CLAIM_FLAGS.RESIDENT,
          rawCredentialBase64: cred.base64Url,
          issuedAt: Date.now(),
          status: "ACTIVE",
        };

        registeredCitizens.push(newCitizen);

        // Generate printable high-res QR code
        const qrDataUrl = await QRCode.toDataURL(cred.base64Url, {
          width: 320,
          margin: 1,
          color: { dark: "#000000", light: "#ffffff" },
        });

        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: true, citizen: newCitizen, qrDataUrl }));
      } catch (err: any) {
        res.writeHead(500, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: false, error: err.message }));
      }
    });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/admin/revoke") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      try {
        const { citizenIndex } = JSON.parse(body);
        const isRevoked = authority.revocationRegistry.isRevoked(citizenIndex);
        if (isRevoked) {
          authority.unrevokeCredential(citizenIndex);
        } else {
          authority.revokeCredential(citizenIndex);
        }

        // Apply to verifier cache
        const manifest = authority.exportSignedRevocationManifest();
        applySignedRevocationManifest(
          manifest,
          new Map([[TANZA_LGU_CODE, authority.getPublicKey()]]),
          verifier.getRevocationRegistry(TANZA_LGU_CODE)!
        );

        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: true, isRevoked: !isRevoked }));
      } catch (err: any) {
        res.writeHead(500, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: false, error: err.message }));
      }
    });
    return;
  }

  // API: Toggle Revocation Status (legacy button)
  if (req.method === "POST" && url.pathname === "/api/authority/toggle-revocation") {
    const isCurrentlyRevoked = authority.revocationRegistry.isRevoked(registeredCitizens[0].citizenIndex);
    if (isCurrentlyRevoked) {
      authority.unrevokeCredential(registeredCitizens[0].citizenIndex);
    } else {
      authority.revokeCredential(registeredCitizens[0].citizenIndex);
    }

    const manifest = authority.exportSignedRevocationManifest();
    applySignedRevocationManifest(
      manifest,
      new Map([[TANZA_LGU_CODE, authority.getPublicKey()]]),
      verifier.getRevocationRegistry(TANZA_LGU_CODE)!
    );

    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ revoked: !isCurrentlyRevoked }));
  }

  // API: Fetch Audit Trail
  if (req.method === "GET" && url.pathname === "/api/verifier/audit-log") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify(verifier.auditLedger.getRecords()));
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not Found");
});

server.listen(PORT, () => {
  console.log(`========================================================================`);
  console.log(`  LGU e-ID DUAL SIMULATION UI ACTIVE: http://localhost:${PORT}`);
  console.log(`  MUNICIPAL ADMIN PORTAL:          http://localhost:${PORT}/admin`);
  console.log(`  CITIZEN POCKETBOOK:              http://localhost:${PORT}/client`);
  console.log(`  INSPECTOR FIELD TERMINAL:        http://localhost:${PORT}/terminal`);
  console.log(`  AIR-GAPPED SYNC STATION:         http://localhost:${PORT}/sync`);
  console.log(`========================================================================`);
});
