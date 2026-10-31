const { Plugin, Setting, Dialog, showMessage, confirmDialog } = require("siyuan");

// ==========================================
// 1. Web Crypto AWS SigV4 Signer & S3 Engine
// ==========================================
class AwsSigV4Signer {
  constructor(credentials) {
    this.accessKey = credentials.accessKey;
    this.secretKey = credentials.secretKey;
    this.region = credentials.region || "us-east-1";
    this.service = "s3";
  }

  static async sha256Hex(data) {
    const buffer = typeof data === "string" ? new TextEncoder().encode(data) : data;
    const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  static async hmacSha256(key, message) {
    const keyData = typeof key === "string" ? new TextEncoder().encode(key) : key;
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const msgData = typeof message === "string" ? new TextEncoder().encode(message) : message;
    return await crypto.subtle.sign("HMAC", cryptoKey, msgData);
  }

  async getSigningKey(dateStamp) {
    const kDate = await AwsSigV4Signer.hmacSha256("AWS4" + this.secretKey, dateStamp);
    const kRegion = await AwsSigV4Signer.hmacSha256(kDate, this.region);
    const kService = await AwsSigV4Signer.hmacSha256(kRegion, this.service);
    return await AwsSigV4Signer.hmacSha256(kService, "aws4_request");
  }

  async signRequest({ method, url, headers = {}, payload = "" }) {
    const parsedUrl = new URL(url);
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
    const dateStamp = amzDate.substring(0, 8);

    headers["host"] = parsedUrl.host;
    headers["x-amz-date"] = amzDate;

    let payloadHash;
    if (payload instanceof ArrayBuffer || ArrayBuffer.isView(payload)) {
      payloadHash = await AwsSigV4Signer.sha256Hex(payload);
    } else if (typeof payload === "string") {
      payloadHash = await AwsSigV4Signer.sha256Hex(payload);
    } else {
      payloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    }
    headers["x-amz-content-sha256"] = payloadHash;

    const sortedHeaderKeys = Object.keys(headers)
      .map((k) => k.toLowerCase())
      .sort();
    const canonicalHeaders =
      sortedHeaderKeys.map((k) => `${k}:${headers[k].toString().trim()}\n`).join("");
    const signedHeaders = sortedHeaderKeys.join(";");

    const queryParams = new URLSearchParams(parsedUrl.search);
    const sortedQuery = Array.from(queryParams.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");

    const canonicalRequest = [
      method,
      parsedUrl.pathname,
      sortedQuery,
      canonicalHeaders,
      signedHeaders,
      payloadHash,
    ].join("\n");

    const credentialScope = `${dateStamp}/${this.region}/${this.service}/aws4_request`;
    const stringToSign = [
      "AWS4-HMAC-SHA256",
      amzDate,
      credentialScope,
      await AwsSigV4Signer.sha256Hex(canonicalRequest),
    ].join("\n");

    const signingKey = await this.getSigningKey(dateStamp);
    const signature = Array.from(new Uint8Array(await AwsSigV4Signer.hmacSha256(signingKey, stringToSign)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    headers["Authorization"] = `AWS4-HMAC-SHA256 Credential=${this.accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return { url, headers };
  }
}

class S3Engine {
  constructor(config) {
    this.endpoint = (config.endpoint || "").replace(/\/+$/, "");
    this.region = config.region || "auto";
    this.bucket = config.bucket;
    this.accessKey = config.accessKey;
    this.secretKey = config.secretKey;
    this.pathStyle = config.pathStyle !== false;
    this.prefix = (config.prefix || "siyuan-backups/").replace(/^\/+/, "");
    this.signer = new AwsSigV4Signer({
      accessKey: this.accessKey,
      secretKey: this.secretKey,
      region: this.region === "auto" ? "us-east-1" : this.region,
    });
  }

  getObjectUrl(key) {
    if (this.pathStyle) {
      return `${this.endpoint}/${this.bucket}/${encodeURIComponent(key).replace(/%2F/g, "/")}`;
    }
    const url = new URL(this.endpoint);
    return `${url.protocol}//${this.bucket}.${url.host}/${encodeURIComponent(key).replace(/%2F/g, "/")}`;
  }

  async testConnection() {
    if (!this.endpoint || !this.bucket || !this.accessKey || !this.secretKey) {
      return { ok: false, msg: "S3 配置不完整：请检查 Endpoint、Bucket、AK、SK" };
    }
    try {
      const url = this.pathStyle
        ? `${this.endpoint}/${this.bucket}?max-keys=1`
        : `${new URL(this.endpoint).protocol}//${this.bucket}.${new URL(this.endpoint).host}?max-keys=1`;
      const { headers } = await this.signer.signRequest({
        method: "GET",
        url,
        headers: {},
      });
      const res = await fetch(url, { method: "GET", headers });
      if (res.status === 200 || res.status === 204) {
        return { ok: true, msg: "S3 连通性测试成功！权限认证正常。" };
      }
      const text = await res.text();
      return { ok: false, msg: `S3 响应错误 (${res.status}): ${text.substring(0, 200)}` };
    } catch (e) {
      return { ok: false, msg: `网络连接失败: ${e.message}` };
    }
  }

  async upload(key, data, contentType = "application/zip") {
    const fullKey = `${this.prefix}${key}`;
    const url = this.getObjectUrl(fullKey);
    const headers = { "content-type": contentType };
    const signed = await this.signer.signRequest({
      method: "PUT",
      url,
      headers,
      payload: data,
    });
    const res = await fetch(signed.url, {
      method: "PUT",
      headers: signed.headers,
      body: data,
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`S3 上传失败 (${res.status}): ${errText}`);
    }
    return { key: fullKey, status: res.status };
  }

  async listBackups() {
    const url = this.pathStyle
      ? `${this.endpoint}/${this.bucket}?prefix=${encodeURIComponent(this.prefix)}`
      : `${new URL(this.endpoint).protocol}//${this.bucket}.${new URL(this.endpoint).host}?prefix=${encodeURIComponent(this.prefix)}`;
    const signed = await this.signer.signRequest({
      method: "GET",
      url,
      headers: {},
    });
    const res = await fetch(signed.url, {
      method: "GET",
      headers: signed.headers,
    });
    if (!res.ok) {
      throw new Error(`获取快照列表失败 (${res.status})`);
    }
    const text = await res.text();
    const parser = new DOMParser();
    const xml = parser.parseFromString(text, "application/xml");
    const contents = xml.querySelectorAll("Contents");
    const files = [];
    contents.forEach((node) => {
      const k = node.querySelector("Key")?.textContent || "";
      const size = parseInt(node.querySelector("Size")?.textContent || "0", 10);
      const lastModified = node.querySelector("LastModified")?.textContent || "";
      if (k && !k.endsWith("/")) {
        files.push({
          key: k,
          name: k.replace(this.prefix, ""),
          size,
          lastModified,
        });
      }
    });
    return files;
  }

  async download(key) {
    const url = this.getObjectUrl(key);
    const signed = await this.signer.signRequest({
      method: "GET",
      url,
      headers: {},
    });
    const res = await fetch(signed.url, {
      method: "GET",
      headers: signed.headers,
    });
    if (!res.ok) throw new Error(`S3 下载失败 (${res.status})`);
    return await res.arrayBuffer();
  }

  async delete(key) {
    const url = this.getObjectUrl(key);
    const signed = await this.signer.signRequest({
      method: "DELETE",
      url,
      headers: {},
    });
    const res = await fetch(signed.url, {
      method: "DELETE",
      headers: signed.headers,
    });
    if (!res.ok && res.status !== 204) {
      throw new Error(`S3 删除失败 (${res.status})`);
    }
    return true;
  }
}

// ==========================================
// 2. WebDAV Storage Engine
// ==========================================
class WebDAVEngine {
  constructor(config) {
    this.endpoint = (config.endpoint || "").replace(/\/+$/, "");
    this.username = config.username || "";
    this.password = config.password || "";
    this.prefix = (config.prefix || "siyuan-backups/").replace(/^\/+|\/+$/g, "");
  }

  getAuthHeader() {
    const token = btoa(`${this.username}:${this.password}`);
    return `Basic ${token}`;
  }

  async ensureDirectory(dirPath) {
    const parts = dirPath.split("/").filter(Boolean);
    let current = this.endpoint;
    for (const part of parts) {
      current += `/${encodeURIComponent(part)}`;
      try {
        await fetch(current, {
          method: "MKCOL",
          headers: { Authorization: this.getAuthHeader() },
        });
      } catch (e) {
        // Ignored if folder already exists
      }
    }
  }

  async testConnection() {
    if (!this.endpoint || !this.username || !this.password) {
      return { ok: false, msg: "WebDAV 配置不完整：请检查地址、账号、密码" };
    }
    try {
      const res = await fetch(this.endpoint, {
        method: "PROPFIND",
        headers: {
          Authorization: this.getAuthHeader(),
          Depth: "0",
        },
      });
      if (res.status >= 200 && res.status < 300) {
        return { ok: true, msg: "WebDAV 连通性测试成功！服务状态正常。" };
      }
      return { ok: false, msg: `WebDAV 认证或连接响应错误 (${res.status})` };
    } catch (e) {
      return { ok: false, msg: `连接 WebDAV 失败: ${e.message}` };
    }
  }

  async upload(key, data, contentType = "application/zip") {
    if (this.prefix) {
      await this.ensureDirectory(this.prefix);
    }
    const fullPath = this.prefix ? `${this.prefix}/${key}` : key;
    const url = `${this.endpoint}/${fullPath.split("/").map(encodeURIComponent).join("/")}`;
    const res = await fetch(url, {
      method: "PUT",
      headers: {
        Authorization: this.getAuthHeader(),
        "Content-Type": contentType,
      },
      body: data,
    });
    if (!res.ok && res.status !== 201 && res.status !== 204) {
      throw new Error(`WebDAV 上传失败 (${res.status})`);
    }
    return { key: fullPath, status: res.status };
  }

  async listBackups() {
    const folderUrl = this.prefix
      ? `${this.endpoint}/${this.prefix.split("/").map(encodeURIComponent).join("/")}/`
      : `${this.endpoint}/`;

    const res = await fetch(folderUrl, {
      method: "PROPFIND",
      headers: {
        Authorization: this.getAuthHeader(),
        Depth: "1",
      },
    });
    if (!res.ok) {
      if (res.status === 404) return [];
      throw new Error(`获取 WebDAV 快照列表失败 (${res.status})`);
    }
    const text = await res.text();
    const parser = new DOMParser();
    const xml = parser.parseFromString(text, "application/xml");
    const responses = xml.querySelectorAll("response, d\\:response");
    const files = [];

    responses.forEach((respNode) => {
      const href = respNode.querySelector("href, d\\:href")?.textContent || "";
      const decodedHref = decodeURIComponent(href);
      const isDir =
        respNode.querySelector("resourcetype collection, d\\:resourcetype d\\:collection") !== null ||
        decodedHref.endsWith("/");
      if (!isDir) {
        const size = parseInt(
          respNode.querySelector("getcontentlength, d\\:getcontentlength")?.textContent || "0",
          10
        );
        const lastModified =
          respNode.querySelector("getlastmodified, d\\:getlastmodified")?.textContent || "";
        const parts = decodedHref.replace(/\/+$/, "").split("/");
        const fileName = parts[parts.length - 1];
        files.push({
          key: this.prefix ? `${this.prefix}/${fileName}` : fileName,
          name: fileName,
          size,
          lastModified,
        });
      }
    });
    return files;
  }

  async download(key) {
    const url = `${this.endpoint}/${key.split("/").map(encodeURIComponent).join("/")}`;
    const res = await fetch(url, {
      method: "GET",
      headers: { Authorization: this.getAuthHeader() },
    });
    if (!res.ok) throw new Error(`WebDAV 下载失败 (${res.status})`);
    return await res.arrayBuffer();
  }

  async delete(key) {
    const url = `${this.endpoint}/${key.split("/").map(encodeURIComponent).join("/")}`;
    const res = await fetch(url, {
      method: "DELETE",
      headers: { Authorization: this.getAuthHeader() },
    });
    if (!res.ok && res.status !== 204 && res.status !== 404) {
      throw new Error(`WebDAV 删除失败 (${res.status})`);
    }
    return true;
  }
}

// ==========================================
// 3. Client-Side AES-256-GCM Zero-Knowledge Crypto
// ==========================================
class CryptoUtil {
  static async deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  static async encrypt(dataBuffer, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await CryptoUtil.deriveKey(password, salt);

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      dataBuffer
    );

    // Format: "SYENC1" (6B) + salt (16B) + iv (12B) + ciphertext
    const header = new TextEncoder().encode("SYENC1");
    const combined = new Uint8Array(header.length + salt.length + iv.length + ciphertext.byteLength);
    combined.set(header, 0);
    combined.set(salt, header.length);
    combined.set(iv, header.length + salt.length);
    combined.set(new Uint8Array(ciphertext), header.length + salt.length + iv.length);

    return combined.buffer;
  }

  static async decrypt(encryptedBuffer, password) {
    const bytes = new Uint8Array(encryptedBuffer);
    const magic = new TextDecoder().decode(bytes.slice(0, 6));
    if (magic !== "SYENC1") {
      throw new Error("不是有效的加密快照文件或版本不兼容！");
    }
    const salt = bytes.slice(6, 22);
    const iv = bytes.slice(22, 34);
    const ciphertext = bytes.slice(34);

    const key = await CryptoUtil.deriveKey(password, salt);
    return await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
  }
}

// ==========================================
// 4. Main Plugin Class
// ==========================================
class CloudBackupPlugin extends Plugin {
  constructor(options) {
    super(options);
    this.storageKey = "cloud_backup_config.json";
    this.logsKey = "cloud_backup_logs.json";
    this.timer = null;
  }

  async onload() {
    console.log("[CloudBackupPro] 正在加载云端备份专家插件...");

    // Default configuration
    this.configData = Object.assign(
      {
        provider: "s3",
        s3: {
          endpoint: "",
          region: "auto",
          bucket: "",
          accessKey: "",
          secretKey: "",
          pathStyle: true,
          prefix: "siyuan-backups/",
        },
        webdav: {
          endpoint: "",
          username: "",
          password: "",
          prefix: "siyuan-backups/",
        },
        encryptEnabled: false,
        encryptPassword: "",
        autoBackupInterval: 0, // 0 = disabled, in minutes: 60, 180, 720, 1440
        retentionCount: 15,
        lastBackupTime: null,
      },
      (await this.loadData(this.storageKey)) || {}
    );

    this.logs = (await this.loadData(this.logsKey)) || [];

    // Register Plugin Setting so the Settings Gear icon appears on the Bazaar card
    this.setting = new Setting({
      confirmCallback: () => {
        this.saveConfig();
      },
    });

    // Add TopBar Icon
    this.addTopBar({
      icon: '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"></path><polyline points="12 11 12 16"></polyline><polyline points="9 13 12 10 15 13"></polyline></svg>',
      title: "云备份专家 (CloudSync Pro)",
      callback: () => this.openQuickMenu(),
    });

    this.initSchedule();
    console.log("[CloudBackupPro] 插件加载完成。");
  }

  onunload() {
    if (this.timer) clearInterval(this.timer);
    console.log("[CloudBackupPro] 插件已卸载。");
  }

  getEngine() {
    if (this.configData.provider === "webdav") {
      return new WebDAVEngine(this.configData.webdav);
    }
    return new S3Engine(this.configData.s3);
  }

  async saveConfig() {
    await this.saveData(this.storageKey, this.configData);
    this.initSchedule();
  }

  async addLog(entry) {
    this.logs.unshift({
      time: new Date().toLocaleString(),
      ...entry,
    });
    if (this.logs.length > 50) this.logs.pop();
    await this.saveData(this.logsKey, this.logs);
  }

  initSchedule() {
    if (this.timer) clearInterval(this.timer);
    const intervalMin = parseInt(this.configData.autoBackupInterval, 10);
    if (intervalMin > 0) {
      console.log(`[CloudBackupPro] 已启用定时自动备份，周期: ${intervalMin} 分钟`);
      this.timer = setInterval(() => {
        this.performBackup({ silent: true, mode: "full" });
      }, intervalMin * 60 * 1000);
    }
  }

  openQuickMenu() {
    const isConfigured =
      this.configData.provider === "s3"
        ? !!(this.configData.s3.endpoint && this.configData.s3.bucket)
        : !!this.configData.webdav.endpoint;

    const lastTime = this.configData.lastBackupTime
      ? new Date(this.configData.lastBackupTime).toLocaleString()
      : "暂无记录";

    const dialog = new Dialog({
      title: "云端备份专家 (CloudSync Pro)",
      content: `
        <div class="csp-modal">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; padding-bottom:10px; border-bottom:1px solid var(--b3-border-color);">
            <div>
              <span style="font-weight:600;">当前存储引擎:</span> 
              <span class="csp-status-badge ${isConfigured ? "success" : "warning"}">
                ${this.configData.provider.toUpperCase()} (${isConfigured ? "已就绪" : "未完整配置"})
              </span>
            </div>
            <div style="font-size:12px; color:var(--b3-theme-on-surface-light);">
              上次备份: ${lastTime}
            </div>
          </div>

          <div style="display:flex; flex-direction:column; gap:8px;">
            <button class="b3-button" id="csp-btn-quick-backup" style="padding:10px; font-weight:600;">
              ⚡ 立即全量备份工作空间
            </button>
            <button class="b3-button b3-button--outline" id="csp-btn-nb-backup">
              📚 备份指定笔记本
            </button>
            <button class="b3-button b3-button--outline" id="csp-btn-browse">
              🔄 云端历史快照与逆向恢复
            </button>
            <button class="b3-button b3-button--text" id="csp-btn-settings">
              ⚙️ 存储与备份设置
            </button>
          </div>
        </div>
      `,
      width: "480px",
    });

    const el = dialog.element;
    el.querySelector("#csp-btn-quick-backup").onclick = () => {
      dialog.destroy();
      this.performBackup({ mode: "full" });
    };
    el.querySelector("#csp-btn-nb-backup").onclick = () => {
      dialog.destroy();
      this.openNotebookSelectDialog();
    };
    el.querySelector("#csp-btn-browse").onclick = () => {
      dialog.destroy();
      this.openCloudBrowserDialog();
    };
    el.querySelector("#csp-btn-settings").onclick = () => {
      dialog.destroy();
      this.openSettingsDialog();
    };
  }

  async performBackup({ mode = "full", notebookId = "", notebookName = "", silent = false }) {
    if (!silent) showMessage("正在生成数据快照并打包，请稍候...", 3000, "info");
    const t0 = Date.now();

    try {
      let exportApiUrl = "/api/export/exportData";
      let postBody = {};
      let backupPrefix = "siyuan-workspace-";

      if (mode === "notebook" && notebookId) {
        exportApiUrl = "/api/export/exportNotebookSY";
        postBody = { id: notebookId };
        backupPrefix = `notebook-${(notebookName || notebookId).replace(/[^a-zA-Z0-9_\u4e00-\u9fa5]/g, "_")}-`;
      }

      // Step 1: Call SiYuan Kernel Export API
      const exportRes = await fetch(exportApiUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(postBody),
      }).then((r) => r.json());

      if (exportRes.code !== 0 || !exportRes.data?.zip) {
        throw new Error(exportRes.msg || "内核打包导出失败");
      }

      const zipDownloadUrl = exportRes.data.zip;

      // Step 2: Fetch the exported zip binary
      if (!silent) showMessage("正在提取快照并准备云端传输...", 3000, "info");
      const zipBlobRes = await fetch(zipDownloadUrl);
      if (!zipBlobRes.ok) throw new Error("获取导出快照流失败");
      let dataBuffer = await zipBlobRes.arrayBuffer();

      const originalSize = dataBuffer.byteLength;
      const sizeMb = (originalSize / (1024 * 1024)).toFixed(2);

      // Step 3: Optional Encryption
      let isEncrypted = false;
      if (this.configData.encryptEnabled && this.configData.encryptPassword) {
        if (!silent) showMessage("正在进行 AES-256-GCM 本地加密...", 2000, "info");
        dataBuffer = await CryptoUtil.encrypt(dataBuffer, this.configData.encryptPassword);
        isEncrypted = true;
      }

      // Step 4: Upload to Cloud Provider
      const engine = this.getEngine();
      const dateStr = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      const encSuffix = isEncrypted ? ".enc" : "";
      const ext = mode === "notebook" ? ".sy.zip" : ".zip";
      const fileName = `${backupPrefix}${dateStr}${encSuffix}${ext}`;

      if (!silent) showMessage(`正在上传快照到 ${this.configData.provider.toUpperCase()}...`, 5000, "info");
      await engine.upload(fileName, dataBuffer);

      const elapsedSec = ((Date.now() - t0) / 1000).toFixed(1);
      this.configData.lastBackupTime = new Date().toISOString();
      await this.saveConfig();

      await this.addLog({
        status: "success",
        mode,
        file: fileName,
        size: `${sizeMb} MB`,
        elapsed: `${elapsedSec}s`,
      });

      if (!silent) {
        showMessage(`🎉 备份成功！耗时: ${elapsedSec}s，快照已上传至云端: ${fileName}`, 6000, "info");
      }

      // Step 5: Lifecycle Pruning
      await this.pruneOldBackups(engine);
    } catch (e) {
      console.error("[CloudBackupPro] Backup failed:", e);
      await this.addLog({
        status: "error",
        mode,
        error: e.message,
      });
      if (!silent) {
        showMessage(`❌ 备份失败: ${e.message}`, 6000, "error");
      }
    }
  }

  async pruneOldBackups(engine) {
    try {
      const maxCount = this.configData.retentionCount || 15;
      const files = await engine.listBackups();
      if (files.length > maxCount) {
        files.sort((a, b) => a.name.localeCompare(b.name));
        const toDelete = files.slice(0, files.length - maxCount);
        for (const f of toDelete) {
          console.log(`[CloudBackupPro] 清理过期快照: ${f.key}`);
          await engine.delete(f.key);
        }
      }
    } catch (e) {
      console.warn("[CloudBackupPro] 生命周期快照清理出错:", e);
    }
  }

  async openNotebookSelectDialog() {
    try {
      const res = await fetch("/api/notebook/lsNotebooks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      }).then((r) => r.json());

      if (res.code !== 0 || !res.data?.notebooks) {
        throw new Error(res.msg || "无法获取笔记本列表");
      }

      const notebooks = res.data.notebooks.filter((n) => !n.closed);
      if (notebooks.length === 0) {
        showMessage("没有已打开的笔记本", 3000, "warning");
        return;
      }

      const optionsHtml = notebooks.map((n) => `<option value="${n.id}">${n.name}</option>`).join("");

      const dialog = new Dialog({
        title: "选择要备份的笔记本 (Single Notebook)",
        content: `
          <div class="csp-modal">
            <div class="csp-form-group">
              <label>选择笔记本</label>
              <select id="csp-select-nb" class="b3-select csp-select">
                ${optionsHtml}
              </select>
            </div>
            <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:16px;">
              <button class="b3-button b3-button--cancel" id="csp-btn-nb-cancel">取消</button>
              <button class="b3-button" id="csp-btn-nb-confirm">立即备份选中笔记本</button>
            </div>
          </div>
        `,
        width: "420px",
      });

      dialog.element.querySelector("#csp-btn-nb-cancel").onclick = () => dialog.destroy();
      dialog.element.querySelector("#csp-btn-nb-confirm").onclick = () => {
        const selNbId = dialog.element.querySelector("#csp-select-nb").value;
        const selNb = notebooks.find((n) => n.id === selNbId);
        dialog.destroy();
        this.performBackup({
          mode: "notebook",
          notebookId: selNbId,
          notebookName: selNb?.name || selNbId,
        });
      };
    } catch (e) {
      showMessage(`获取笔记本列表失败: ${e.message}`, 4000, "error");
    }
  }

  async restoreSnapshot(key, name) {
    confirmDialog(
      "确认逆向恢复数据到思源",
      `⚠️ 警告：恢复操作将把云端快照 [${name}] 的数据逆向导入并合并/还原到思源笔记中！\n建议在恢复前先进行一次当前数据备份。\n\n是否确认从云端逆向恢复？`,
      async () => {
        showMessage(`正在从云端下载快照 [${name}]...`, 10000, "info");
        try {
          const engine = this.getEngine();
          let buf = await engine.download(key);
          if (name.includes(".enc.")) {
            let pass = this.configData.encryptPassword;
            if (!pass) {
              pass = prompt("该快照已启用 AES-256 加密，请输入解密密码：");
              if (!pass) {
                showMessage("已取消恢复：未提供解密密码", 3000, "warning");
                return;
              }
            }
            showMessage("正在解密云端快照数据...", 5000, "info");
            buf = await CryptoUtil.decrypt(buf, pass);
          }

          showMessage("正在逆向还原数据到思源笔记内核...", 10000, "info");
          const isNotebook = name.includes(".sy.zip");
          const plainName = name.replace(".enc.", ".");
          const blob = new Blob([buf], { type: "application/zip" });
          const file = new File([blob], plainName, { type: "application/zip" });

          const formData = new FormData();
          formData.append("file", file);

          if (isNotebook) {
            // Restore single notebook via /api/import/importSYNotebook
            const resp = await fetch("/api/import/importSYNotebook", {
              method: "POST",
              body: formData,
            });
            const result = await resp.json();
            if (result.code !== 0) {
              throw new Error(result.msg || "导入笔记本失败");
            }
            showMessage(`🎉 笔记本 [${plainName}] 逆向恢复成功！`, 4000, "info");
          } else {
            // Restore full workspace via /api/import/importData
            const resp = await fetch("/api/import/importData", {
              method: "POST",
              body: formData,
            });
            const result = await resp.json();
            if (result.code !== 0) {
              throw new Error(result.msg || "导入数据失败");
            }
            confirmDialog(
              "逆向恢复成功",
              "🎉 工作空间数据已成功从云端逆向恢复！\n需要刷新思源界面以完整展示最新数据，是否立即刷新？",
              () => {
                window.location.reload();
              }
            );
          }

          await this.addLog({
            action: "restore",
            status: "success",
            provider: this.configData.provider,
            target: name,
            message: "从云端逆向恢复成功",
          });
        } catch (e) {
          console.error("[CloudBackupPro] Restore failed:", e);
          showMessage(`❌ 恢复失败: ${e.message}`, 5000, "error");
          await this.addLog({
            action: "restore",
            status: "fail",
            provider: this.configData.provider,
            target: name,
            message: e.message,
          });
        }
      }
    );
  }

  async renderSnapshotList(container) {
    container.innerHTML = '<div style="text-align:center; padding:30px; color:var(--b3-theme-on-surface-light);">正在拉取云端快照列表...</div>';
    try {
      const engine = this.getEngine();
      const items = await engine.listBackups();
      if (items.length === 0) {
        container.innerHTML = '<div style="text-align:center; padding:40px; color:var(--b3-theme-on-surface-light);">云端暂无快照文件</div>';
        return;
      }

      // Sort latest first
      items.sort((a, b) => b.name.localeCompare(a.name));

      container.innerHTML = items
        .map((item) => {
          const sizeMb = (item.size / (1024 * 1024)).toFixed(2);
          const dateStr = item.lastModified ? new Date(item.lastModified).toLocaleString() : item.name;
          const isEnc = item.name.includes(".enc.");
          const isNb = item.name.includes(".sy.zip");
          const typeBadge = isNb
            ? '<span style="background:rgba(33,150,243,0.15); color:#1976d2; padding:2px 6px; border-radius:4px; font-size:11px;">单笔记本</span>'
            : '<span style="background:rgba(76,175,80,0.15); color:#2e7d32; padding:2px 6px; border-radius:4px; font-size:11px;">全工作区</span>';

          return `
            <div class="csp-snapshot-item">
              <div class="csp-snapshot-info">
                <div class="csp-snapshot-name">
                  ${item.name} ${typeBadge} ${isEnc ? '<span style="color:#ed6c02; font-size:11px;">[AES加密]</span>' : ""}
                </div>
                <div class="csp-snapshot-meta">
                  大小: ${sizeMb} MB &nbsp;|&nbsp; 上传时间: ${dateStr}
                </div>
              </div>
              <div style="display:flex; gap:6px; align-items:center;">
                <button class="b3-button csp-restore-btn" data-key="${item.key}" data-name="${item.name}" title="将该云端快照逆向导入并恢复到思源笔记中">
                  📥 逆向恢复
                </button>
                <button class="b3-button b3-button--outline csp-download-btn" data-key="${item.key}" data-name="${item.name}" title="下载解密后的快照包到电脑">
                  💾 下载
                </button>
                <button class="b3-button b3-button--cancel csp-delete-btn" data-key="${item.key}" title="从云端永久删除此备份">
                  🗑️
                </button>
              </div>
            </div>
          `;
        })
        .join("");

      // Bind restore
      container.querySelectorAll(".csp-restore-btn").forEach((btn) => {
        btn.onclick = () => {
          const key = btn.getAttribute("data-key");
          const name = btn.getAttribute("data-name");
          this.restoreSnapshot(key, name);
        };
      });

      // Bind download
      container.querySelectorAll(".csp-download-btn").forEach((btn) => {
        btn.onclick = async () => {
          const key = btn.getAttribute("data-key");
          const name = btn.getAttribute("data-name");
          showMessage(`正在下载快照 ${name}...`, 3000, "info");
          try {
            const engine = this.getEngine();
            let buf = await engine.download(key);
            if (name.includes(".enc.")) {
              let pass = this.configData.encryptPassword;
              if (!pass) {
                pass = prompt("该快照已加密，请输入解密密码：");
                if (!pass) return;
              }
              buf = await CryptoUtil.decrypt(buf, pass);
            }
            const blob = new Blob([buf], { type: "application/zip" });
            const a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = name.replace(".enc.", ".");
            a.click();
            showMessage("快照下载已启动！", 3000, "info");
          } catch (e) {
            showMessage(`下载失败: ${e.message}`, 4000, "error");
          }
        };
      });

      // Bind delete
      container.querySelectorAll(".csp-delete-btn").forEach((btn) => {
        btn.onclick = () => {
          const key = btn.getAttribute("data-key");
          confirmDialog("确认删除云端备份", `确定要永久删除云端快照 [${key}] 吗？`, async () => {
            try {
              const engine = this.getEngine();
              await engine.delete(key);
              showMessage("快照已从云端删除", 2000, "info");
              this.renderSnapshotList(container);
            } catch (e) {
              showMessage(`删除失败: ${e.message}`, 4000, "error");
            }
          });
        };
      });
    } catch (e) {
      container.innerHTML = `<div style="text-align:center; padding:30px; color:#d32f2f;">获取失败: ${e.message}</div>`;
    }
  }

  async openCloudBrowserDialog() {
    const dialog = new Dialog({
      title: "云端历史快照管理与逆向恢复 (Cloud Restore)",
      content: `
        <div class="csp-modal" style="min-height:360px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <div style="font-size:12px; color:var(--b3-theme-on-surface-light);">
              当前存储引擎: <strong>${this.configData.provider.toUpperCase()}</strong>
            </div>
            <button class="b3-button b3-button--outline" id="csp-browser-refresh">🔄 刷新列表</button>
          </div>
          <div id="csp-browser-list" style="max-height:420px; overflow-y:auto; padding-right:4px;">
            <div style="text-align:center; padding:30px; color:var(--b3-theme-on-surface-light);">正在拉取云端快照列表...</div>
          </div>
        </div>
      `,
      width: "720px",
    });

    const refreshList = () => {
      const container = dialog.element.querySelector("#csp-browser-list");
      this.renderSnapshotList(container);
    };

    dialog.element.querySelector("#csp-browser-refresh").onclick = refreshList;
    refreshList();
  }

  openSetting() {
    this.openSettingsDialog();
  }

  openSettingsDialog() {
    const cfg = this.configData;
    const dialog = new Dialog({
      title: "云端备份专家设置 (CloudSync Pro Settings)",
      content: `
        <div class="csp-modal" style="width:680px;">
          <div class="csp-tabs">
            <button class="csp-tab-btn active" data-tab="tab-storage">存储提供商</button>
            <button class="csp-tab-btn" data-tab="tab-backup-restore">手动备份与逆向恢复</button>
            <button class="csp-tab-btn" data-tab="tab-plan">自动计划与加密</button>
            <button class="csp-tab-btn" data-tab="tab-logs">备份日志</button>
          </div>

          <!-- Tab 1: Storage -->
          <div id="tab-storage" class="csp-tab-content">
            <div class="csp-form-group">
              <label>选择云存储协议</label>
              <select id="cfg-provider" class="b3-select csp-select">
                <option value="s3" ${cfg.provider === "s3" ? "selected" : ""}>S3 协议 (MinIO, R2, AWS, 阿里云, 腾讯云等)</option>
                <option value="webdav" ${cfg.provider === "webdav" ? "selected" : ""}>WebDAV (坚果云, Nextcloud, 群晖等)</option>
              </select>
            </div>

            <!-- S3 Form -->
            <div id="panel-s3" style="${cfg.provider === "s3" ? "" : "display:none;"}">
              <div class="csp-form-group">
                <label>S3 Endpoint</label>
                <div class="csp-desc">如: https://s3.amazonaws.com 或 https://&lt;account-id&gt;.r2.cloudflarestorage.com</div>
                <input class="b3-text-field csp-input" id="s3-endpoint" value="${cfg.s3.endpoint || ""}" placeholder="https://..." />
              </div>
              <div style="display:flex; gap:12px;">
                <div class="csp-form-group" style="flex:1;">
                  <label>Bucket (存储桶名)</label>
                  <input class="b3-text-field csp-input" id="s3-bucket" value="${cfg.s3.bucket || ""}" />
                </div>
                <div class="csp-form-group" style="flex:1;">
                  <label>Region (区域)</label>
                  <input class="b3-text-field csp-input" id="s3-region" value="${cfg.s3.region || "auto"}" />
                </div>
              </div>
              <div style="display:flex; gap:12px;">
                <div class="csp-form-group" style="flex:1;">
                  <label>Access Key</label>
                  <input class="b3-text-field csp-input" id="s3-access" value="${cfg.s3.accessKey || ""}" />
                </div>
                <div class="csp-form-group" style="flex:1;">
                  <label>Secret Key</label>
                  <input type="password" class="b3-text-field csp-input" id="s3-secret" value="${cfg.s3.secretKey || ""}" />
                </div>
              </div>
              <div class="csp-form-group">
                <label>云端目录前缀</label>
                <input class="b3-text-field csp-input" id="s3-prefix" value="${cfg.s3.prefix || "siyuan-backups/"}" />
              </div>
            </div>

            <!-- WebDAV Form -->
            <div id="panel-webdav" style="${cfg.provider === "webdav" ? "" : "display:none;"}">
              <div class="csp-form-group">
                <label>WebDAV 地址</label>
                <div class="csp-desc">如: https://dav.jianguoyun.com/dav/ 或 https://nas.local:5006/siyuan/</div>
                <input class="b3-text-field csp-input" id="dav-endpoint" value="${cfg.webdav.endpoint || ""}" placeholder="https://..." />
              </div>
              <div style="display:flex; gap:12px;">
                <div class="csp-form-group" style="flex:1;">
                  <label>用户名 (Username)</label>
                  <input class="b3-text-field csp-input" id="dav-username" value="${cfg.webdav.username || ""}" />
                </div>
                <div class="csp-form-group" style="flex:1;">
                  <label>应用授权密码 (Password)</label>
                  <input type="password" class="b3-text-field csp-input" id="dav-password" value="${cfg.webdav.password || ""}" />
                </div>
              </div>
              <div class="csp-form-group">
                <label>云端存储子目录</label>
                <input class="b3-text-field csp-input" id="dav-prefix" value="${cfg.webdav.prefix || "siyuan-backups/"}" />
              </div>
            </div>

            <div style="margin-top:14px;">
              <button class="b3-button b3-button--outline" id="cfg-btn-test">🔌 测试当前云端连接</button>
            </div>
          </div>

          <!-- Tab 2: Manual Backup & Reverse Restore -->
          <div id="tab-backup-restore" class="csp-tab-content" style="display:none;">
            <!-- Section A: Manual Backup -->
            <div style="background:var(--b3-theme-surface); border:1px solid var(--b3-border-color); border-radius:8px; padding:14px; margin-bottom:16px;">
              <div style="font-weight:600; font-size:14px; margin-bottom:10px; display:flex; align-items:center; gap:6px;">
                ⚡ 手动执行备份 (Manual Backup Now)
              </div>
              <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
                <button class="b3-button" id="cfg-btn-manual-full" style="padding:8px 16px; font-weight:600;">
                  ⚡ 立即全量备份工作空间
                </button>
                <div style="display:flex; align-items:center; gap:6px;">
                  <select id="cfg-manual-nb-select" class="b3-select" style="max-width:200px;">
                    <option value="">加载中...</option>
                  </select>
                  <button class="b3-button b3-button--outline" id="cfg-btn-manual-nb">
                    📚 备份选中文档库
                  </button>
                </div>
              </div>
            </div>

            <!-- Section B: Cloud Snapshots & Reverse Restore -->
            <div>
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                <div style="font-weight:600; font-size:14px; display:flex; align-items:center; gap:6px;">
                  🔄 云端历史快照与逆向恢复 (Cloud Restore)
                </div>
                <button class="b3-button b3-button--outline" id="cfg-btn-refresh-snapshots" style="font-size:12px;">
                  🔄 刷新云端快照
                </button>
              </div>
              <div class="csp-desc" style="margin-bottom:8px;">
                支持从云端（S3 或 WebDAV）一键逆向恢复数据到思源笔记，或下载解密副本：
              </div>
              <div id="cfg-snapshots-container" style="max-height:260px; overflow-y:auto; border:1px solid var(--b3-border-color); border-radius:6px; padding:8px; background:var(--b3-theme-background);">
                <div style="text-align:center; padding:20px; color:var(--b3-theme-on-surface-light);">正在拉取云端快照...</div>
              </div>
            </div>
          </div>

          <!-- Tab 3: Plan & Encryption -->
          <div id="tab-plan" class="csp-tab-content" style="display:none;">
            <div class="csp-form-group">
              <label>定时自动备份周期</label>
              <select id="cfg-auto-interval" class="b3-select csp-select">
                <option value="0" ${cfg.autoBackupInterval == 0 ? "selected" : ""}>禁用自动定时备份 (仅手动)</option>
                <option value="60" ${cfg.autoBackupInterval == 60 ? "selected" : ""}>每 1 小时自动备份一次</option>
                <option value="180" ${cfg.autoBackupInterval == 180 ? "selected" : ""}>每 3 小时自动备份一次</option>
                <option value="720" ${cfg.autoBackupInterval == 720 ? "selected" : ""}>每 12 小时自动备份一次</option>
                <option value="1440" ${cfg.autoBackupInterval == 1440 ? "selected" : ""}>每天自动备份一次</option>
              </select>
            </div>

            <div class="csp-form-group">
              <label>云端保留快照数量上限</label>
              <div class="csp-desc">超过该数量时自动修剪并删除最旧的云端快照，防止存储空间爆满</div>
              <input type="number" class="b3-text-field csp-input" id="cfg-retention" value="${cfg.retentionCount || 15}" min="1" max="200" />
            </div>

            <div style="border-top:1px solid var(--b3-border-color); margin:16px 0; padding-top:14px;">
              <div class="csp-form-group">
                <label style="display:flex; align-items:center; gap:8px;">
                  <input type="checkbox" id="cfg-encrypt-enable" ${cfg.encryptEnabled ? "checked" : ""} />
                  启用 AES-256-GCM 端到端强加密
                </label>
                <div class="csp-desc">在上传前进行本地认证加密。请务必牢记密码，丢失将无法恢复数据！</div>
              </div>
              <div class="csp-form-group">
                <label>加密密钥 / 备份密码</label>
                <input type="password" class="b3-text-field csp-input" id="cfg-encrypt-pass" value="${cfg.encryptPassword || ""}" placeholder="输入您的私有专属加密密码" />
              </div>
            </div>
          </div>

          <!-- Tab 4: Logs -->
          <div id="tab-logs" class="csp-tab-content" style="display:none;">
            <div class="csp-log-box" id="cfg-logs-view">
              ${
                this.logs.length === 0
                  ? "暂无备份执行日志"
                  : this.logs
                      .map((l) => `[${l.time}] [${l.status}] ${l.action ? "操作:" + l.action : ""} ${l.mode ? "模式:" + l.mode : ""} ${l.file || l.target ? "目标:" + (l.file || l.target) : ""} ${l.size ? "大小:" + l.size : ""} ${l.elapsed ? "耗时:" + l.elapsed : ""} ${l.error || l.message ? "详情:" + (l.error || l.message) : ""}`)
                      .join("\n")
              }
            </div>
          </div>

          <!-- Actions Footer -->
          <div style="display:flex; justify-content:space-between; align-items:center; margin-top:20px; padding-top:12px; border-top:1px solid var(--b3-border-color);">
            <div>
              <button class="b3-button b3-button--outline" id="cfg-btn-footer-backup" style="font-weight:600; border-color:var(--b3-theme-primary); color:var(--b3-theme-primary);" title="立即对当前工作空间执行一次完整手动备份并上传">
                ⚡ 立即手动备份工作空间
              </button>
            </div>
            <div style="display:flex; gap:8px;">
              <button class="b3-button b3-button--cancel" id="cfg-btn-cancel">取消</button>
              <button class="b3-button" id="cfg-btn-save">保存所有设置</button>
            </div>
          </div>
        </div>
      `,
      width: "720px",
    });

    const el = dialog.element;

    // Tabs switching
    el.querySelectorAll(".csp-tab-btn").forEach((btn) => {
      btn.onclick = () => {
        el.querySelectorAll(".csp-tab-btn").forEach((b) => b.classList.remove("active"));
        el.querySelectorAll(".csp-tab-content").forEach((c) => (c.style.display = "none"));
        btn.classList.add("active");
        const targetId = btn.getAttribute("data-tab");
        el.querySelector(`#${targetId}`).style.display = "block";
        if (targetId === "tab-backup-restore") {
          loadSnapshots();
        }
      };
    });

    // Provider select
    const providerSelect = el.querySelector("#cfg-provider");
    providerSelect.onchange = () => {
      const val = providerSelect.value;
      el.querySelector("#panel-s3").style.display = val === "s3" ? "block" : "none";
      el.querySelector("#panel-webdav").style.display = val === "webdav" ? "block" : "none";
    };

    // Load Notebooks into select
    fetch("/api/notebook/lsNotebooks", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    })
      .then((r) => r.json())
      .then((res) => {
        const nbSelect = el.querySelector("#cfg-manual-nb-select");
        if (res.code === 0 && res.data?.notebooks) {
          const opened = res.data.notebooks.filter((n) => !n.closed);
          if (opened.length > 0) {
            nbSelect.innerHTML = opened.map((n) => `<option value="${n.id}">${n.name}</option>`).join("");
          } else {
            nbSelect.innerHTML = '<option value="">无打开的笔记本</option>';
          }
        }
      })
      .catch(() => {});

    // Manual Full Backup from Tab
    el.querySelector("#cfg-btn-manual-full").onclick = () => {
      this.syncFormToConfig(el);
      this.performBackup({ mode: "full" });
    };

    // Manual Notebook Backup from Tab
    el.querySelector("#cfg-btn-manual-nb").onclick = () => {
      const nbSelect = el.querySelector("#cfg-manual-nb-select");
      const nbId = nbSelect.value;
      const nbName = nbSelect.options[nbSelect.selectedIndex]?.text || nbId;
      if (!nbId) {
        showMessage("请先选择一个有效的笔记本", 3000, "warning");
        return;
      }
      this.syncFormToConfig(el);
      this.performBackup({ mode: "notebook", notebookId: nbId, notebookName: nbName });
    };

    // Load & Refresh Snapshots in Tab 2
    const loadSnapshots = () => {
      const snapshotContainer = el.querySelector("#cfg-snapshots-container");
      this.renderSnapshotList(snapshotContainer);
    };
    el.querySelector("#cfg-btn-refresh-snapshots").onclick = loadSnapshots;

    // Test Connection
    el.querySelector("#cfg-btn-test").onclick = async () => {
      showMessage("正在测试云存储连接...", 3000, "info");
      const provider = providerSelect.value;
      let tempEngine;
      if (provider === "s3") {
        tempEngine = new S3Engine({
          endpoint: el.querySelector("#s3-endpoint").value,
          bucket: el.querySelector("#s3-bucket").value,
          region: el.querySelector("#s3-region").value,
          accessKey: el.querySelector("#s3-access").value,
          secretKey: el.querySelector("#s3-secret").value,
          prefix: el.querySelector("#s3-prefix").value,
        });
      } else {
        tempEngine = new WebDAVEngine({
          endpoint: el.querySelector("#dav-endpoint").value,
          username: el.querySelector("#dav-username").value,
          password: el.querySelector("#dav-password").value,
          prefix: el.querySelector("#dav-prefix").value,
        });
      }

      try {
        const testRes = await tempEngine.testConnection();
        if (testRes.ok) {
          showMessage(testRes.msg, 5000, "info");
        } else {
          showMessage(`❌ ${testRes.msg}`, 6000, "error");
        }
      } catch (err) {
        showMessage(`❌ 连接异常: ${err.message}`, 6000, "error");
      }
    };

    // Footer backup button
    el.querySelector("#cfg-btn-footer-backup").onclick = () => {
      this.syncFormToConfig(el);
      this.performBackup({ mode: "full" });
    };

    el.querySelector("#cfg-btn-cancel").onclick = () => dialog.destroy();
    el.querySelector("#cfg-btn-save").onclick = async () => {
      this.syncFormToConfig(el);
      await this.saveConfig();
      showMessage("✅ 设置已保存！", 3000, "info");
      dialog.destroy();
    };
  }

  syncFormToConfig(el) {
    const providerSelect = el.querySelector("#cfg-provider");
    this.configData.provider = providerSelect.value;
    this.configData.s3.endpoint = el.querySelector("#s3-endpoint").value.trim();
    this.configData.s3.bucket = el.querySelector("#s3-bucket").value.trim();
    this.configData.s3.region = el.querySelector("#s3-region").value.trim();
    this.configData.s3.accessKey = el.querySelector("#s3-access").value.trim();
    this.configData.s3.secretKey = el.querySelector("#s3-secret").value.trim();
    this.configData.s3.prefix = el.querySelector("#s3-prefix").value.trim();

    this.configData.webdav.endpoint = el.querySelector("#dav-endpoint").value.trim();
    this.configData.webdav.username = el.querySelector("#dav-username").value.trim();
    this.configData.webdav.password = el.querySelector("#dav-password").value.trim();
    this.configData.webdav.prefix = el.querySelector("#dav-prefix").value.trim();

    this.configData.autoBackupInterval = parseInt(el.querySelector("#cfg-auto-interval").value, 10);
    this.configData.retentionCount = parseInt(el.querySelector("#cfg-retention").value, 10) || 15;
    this.configData.encryptEnabled = el.querySelector("#cfg-encrypt-enable").checked;
    this.configData.encryptPassword = el.querySelector("#cfg-encrypt-pass").value;
  }
}

module.exports = {
  default: CloudBackupPlugin,
};
