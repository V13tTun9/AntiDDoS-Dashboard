/**
 * CrowdSec Manager Frontend Application
 * Quản trị 2 Tab chính:
 * 1. Tab Decisions: Quản lý IP bị chặn (cscli decisions list/add/delete)
 * 2. Tab Scenarios: Quản lý kịch bản bảo mật (cscli scenarios list/install/remove & /etc/crowdsec/scenarios/)
 */

// Application State
const state = {
  activeTab: "tabDecisionsView", // "tabDecisionsView" hoặc "tabScenariosView"

  // Decisions State
  decisions: [],
  filteredDecisions: [],
  searchQuery: "",
  includeAll: false,
  autoRefreshInterval: 10,
  timerId: null,
  sortColumn: "id",
  sortDirection: "desc",
  selectedForDelete: null,
  isLoadingDecisions: false,

  // Scenarios State
  scenarios: [],
  filteredScenarios: [],
  scenariosSearchQuery: "",
  scenariosFilterType: "all",
  scenariosIncludeAll: false,
  scenariosSortColumn: "name",
  scenariosSortDirection: "asc",
  selectedScenarioForDelete: null,
  selectedScenarioForEdit: null,
  isLoadingScenarios: false,

  // Tab 3: System Metrics State
  system: {
    timerId: null,
    pollInterval: 2000,
    isPaused: false,
    isLoading: false,
    selectedInterface: "all",
    lastData: null,
    history: {
      maxPoints: 60,
      labels: [],
      cpu: [],
      ram: [],
      rx: [],
      tx: []
    }
  }
};

// Preset Scenario Templates
const SCENARIO_TEMPLATES = {
  leaky: `type: leaky
name: custom/ddos-flood-detection
description: "Phat hien tan cong Volumetric Flood (SYN, UDP, HTTP) tuong tu Suricata"
filter: "evt.Meta.log_type in ['suricata_alert', 'nginx_access-log']"
groupby: evt.Meta.source_ip
capacity: 5
leakspeed: 10s
blackhole: 2m
labels:
  service: network
  remediation: true
  type: ban
  behavior: "network:flood"
  label: "Custom Flood Attack Detected"
`,
  trigger: `type: trigger
name: custom/instant-threat-block
description: "Chan ngay lap tuc khi phat hien request chua ma doc"
filter: "evt.Meta.log_type == 'nginx_access-log' && (evt.Parsed.request contains '/wp-config' || evt.Parsed.request contains '/.env')"
groupby: evt.Meta.source_ip
labels:
  service: http
  remediation: true
  type: ban
  behavior: "http:exploit"
  label: "Instant Threat Blocked"
`,
  counter: `type: counter
name: custom/rate-limit-exceeded
description: "Gioi han tan suat truy cap API hoac Website"
filter: "evt.Meta.log_type == 'nginx_access-log'"
groupby: evt.Meta.source_ip
capacity: 120
duration: 1m
labels:
  service: http
  remediation: true
  type: ban
  label: "Rate Limit Exceeded"
`
};

// DOM Elements
const elements = {
  // Navigation & Drawer
  hamburgerBtn: document.getElementById("hamburgerBtn"),
  sidebarDrawer: document.getElementById("sidebarDrawer"),
  sidebarBackdrop: document.getElementById("sidebarBackdrop"),
  sidebarCloseBtn: document.getElementById("sidebarCloseBtn"),
  tabNavDecisions: document.getElementById("tabNavDecisions"),
  tabNavScenarios: document.getElementById("tabNavScenarios"),
  tabNavSystem: document.getElementById("tabNavSystem"),
  badgeDecisionsCount: document.getElementById("badgeDecisionsCount"),
  badgeScenariosCount: document.getElementById("badgeScenariosCount"),
  badgeSystemStatus: document.getElementById("badgeSystemStatus"),
  tabDecisionsView: document.getElementById("tabDecisionsView"),
  tabScenariosView: document.getElementById("tabScenariosView"),
  tabSystemView: document.getElementById("tabSystemView"),
  pageTitle: document.getElementById("pageTitle"),
  pageSubtitle: document.getElementById("pageSubtitle"),

  // Common Header
  rootBadge: document.getElementById("rootBadge"),
  rootBadgeText: document.getElementById("rootBadgeText"),
  permissionWarning: document.getElementById("permissionWarning"),
  enableDemoBtn: document.getElementById("enableDemoBtn"),
  themeToggleBtn: document.getElementById("themeToggleBtn"),
  themeToggleText: document.getElementById("themeToggleText"),
  openAddModalBtn: document.getElementById("openAddModalBtn"),
  openAddModalText: document.getElementById("openAddModalText"),

  // Tab 1: Decisions
  statTotalBans: document.getElementById("statTotalBans"),
  statLocalBans: document.getElementById("statLocalBans"),
  statCapiBans: document.getElementById("statCapiBans"),
  statLastUpdated: document.getElementById("statLastUpdated"),
  statRefreshInterval: document.getElementById("statRefreshInterval"),
  searchInput: document.getElementById("searchInput"),
  clearSearchBtn: document.getElementById("clearSearchBtn"),
  includeAllCheckbox: document.getElementById("includeAllCheckbox"),
  autoRefreshSelect: document.getElementById("autoRefreshSelect"),
  refreshBtn: document.getElementById("refreshBtn"),
  refreshIcon: document.getElementById("refreshIcon"),
  decisionsTable: document.getElementById("decisionsTable"),
  decisionsTableBody: document.getElementById("decisionsTableBody"),
  rowCountBadge: document.getElementById("rowCountBadge"),
  cliCommandHint: document.getElementById("cliCommandHint"),
  filterResultText: document.getElementById("filterResultText"),

  // Tab 2: Scenarios
  statScenariosTotal: document.getElementById("statScenariosTotal"),
  statScenariosEnabled: document.getElementById("statScenariosEnabled"),
  statScenariosDisabled: document.getElementById("statScenariosDisabled"),
  statScenariosLocal: document.getElementById("statScenariosLocal"),
  scenarioSearchInput: document.getElementById("scenarioSearchInput"),
  clearScenarioSearchBtn: document.getElementById("clearScenarioSearchBtn"),
  scenarioFilterSelect: document.getElementById("scenarioFilterSelect"),
  scenarioIncludeAllCheckbox: document.getElementById("scenarioIncludeAllCheckbox"),
  refreshScenariosBtn: document.getElementById("refreshScenariosBtn"),
  refreshScenariosIcon: document.getElementById("refreshScenariosIcon"),
  openAddScenarioBtn: document.getElementById("openAddScenarioBtn"),
  scenariosTable: document.getElementById("scenariosTable"),
  scenariosTableBody: document.getElementById("scenariosTableBody"),
  scenariosCountBadge: document.getElementById("scenariosCountBadge"),
  cliScenarioCommandHint: document.getElementById("cliScenarioCommandHint"),
  scenariosFilterResultText: document.getElementById("scenariosFilterResultText"),

  // Modals - Add Decision
  addModal: document.getElementById("addModal"),
  closeAddModalBtn: document.getElementById("closeAddModalBtn"),
  cancelAddBtn: document.getElementById("cancelAddBtn"),
  addDecisionForm: document.getElementById("addDecisionForm"),
  targetInput: document.getElementById("targetInput"),
  durationInput: document.getElementById("durationInput"),
  durationChips: document.getElementById("durationChips"),
  typeSelect: document.getElementById("typeSelect"),
  reasonInput: document.getElementById("reasonInput"),
  cliAddPreview: document.getElementById("cliAddPreview"),
  submitAddBtn: document.getElementById("submitAddBtn"),

  // Modals - Delete Decision
  deleteModal: document.getElementById("deleteModal"),
  closeDeleteModalBtn: document.getElementById("closeDeleteModalBtn"),
  cancelDeleteBtn: document.getElementById("cancelDeleteBtn"),
  confirmDeleteBtn: document.getElementById("confirmDeleteBtn"),
  deleteTargetValue: document.getElementById("deleteTargetValue"),
  deleteTargetReason: document.getElementById("deleteTargetReason"),
  deleteTargetId: document.getElementById("deleteTargetId"),
  cliDeletePreview: document.getElementById("cliDeletePreview"),

  // Modals - Add Scenario
  addScenarioModal: document.getElementById("addScenarioModal"),
  closeAddScenarioModalBtn: document.getElementById("closeAddScenarioModalBtn"),
  cancelAddScenarioBtn: document.getElementById("cancelAddScenarioBtn"),
  addScenarioForm: document.getElementById("addScenarioForm"),
  scenarioFilenameInput: document.getElementById("scenarioFilenameInput"),
  previewSavePath: document.getElementById("previewSavePath"),
  scenarioContentInput: document.getElementById("scenarioContentInput"),
  submitAddScenarioBtn: document.getElementById("submitAddScenarioBtn"),

  // Modals - Edit Scenario
  editScenarioModal: document.getElementById("editScenarioModal"),
  closeEditScenarioModalBtn: document.getElementById("closeEditScenarioModalBtn"),
  cancelEditScenarioBtn: document.getElementById("cancelEditScenarioBtn"),
  editScenarioForm: document.getElementById("editScenarioForm"),
  editModalTitle: document.getElementById("editModalTitle"),
  editModalSubtitle: document.getElementById("editModalSubtitle"),
  editScenarioNameText: document.getElementById("editScenarioNameText"),
  editScenarioTypeText: document.getElementById("editScenarioTypeText"),
  editScenarioContentInput: document.getElementById("editScenarioContentInput"),
  submitEditScenarioBtn: document.getElementById("submitEditScenarioBtn"),

  // Modals - Delete Scenario
  deleteScenarioModal: document.getElementById("deleteScenarioModal"),
  closeDeleteScenarioModalBtn: document.getElementById("closeDeleteScenarioModalBtn"),
  cancelDeleteScenarioBtn: document.getElementById("cancelDeleteScenarioBtn"),
  confirmDeleteScenarioBtn: document.getElementById("confirmDeleteScenarioBtn"),
  deleteScenarioName: document.getElementById("deleteScenarioName"),
  deleteScenarioType: document.getElementById("deleteScenarioType"),
  deleteScenarioPath: document.getElementById("deleteScenarioPath"),
  cliScenarioDeletePreview: document.getElementById("cliScenarioDeletePreview"),

  // Tab 3: System Metrics Elements
  sysLiveStatusText: document.getElementById("sysLiveStatusText"),
  sysHostText: document.getElementById("sysHostText"),
  sysUptimeText: document.getElementById("sysUptimeText"),
  sysIfaceSelect: document.getElementById("sysIfaceSelect"),
  sysRefreshIntervalSelect: document.getElementById("sysRefreshIntervalSelect"),
  sysPauseResumeBtn: document.getElementById("sysPauseResumeBtn"),
  sysPauseResumeIcon: document.getElementById("sysPauseResumeIcon"),
  sysPauseResumeText: document.getElementById("sysPauseResumeText"),
  sysRefreshOnceBtn: document.getElementById("sysRefreshOnceBtn"),

  // CPU
  sysCpuVal: document.getElementById("sysCpuVal"),
  sysCpuTrend: document.getElementById("sysCpuTrend"),
  sysCpuBar: document.getElementById("sysCpuBar"),
  sysCpuCoresBadge: document.getElementById("sysCpuCoresBadge"),
  sysCpuModelBrief: document.getElementById("sysCpuModelBrief"),
  sysCpuCoresBrief: document.getElementById("sysCpuCoresBrief"),

  // RAM
  sysRamVal: document.getElementById("sysRamVal"),
  sysRamRatio: document.getElementById("sysRamRatio"),
  sysRamBar: document.getElementById("sysRamBar"),
  sysRamTotalBadge: document.getElementById("sysRamTotalBadge"),
  sysRamDetailText: document.getElementById("sysRamDetailText"),
  sysSwapBrief: document.getElementById("sysSwapBrief"),

  // Network RX/TX
  sysRxRateVal: document.getElementById("sysRxRateVal"),
  sysRxPktsBrief: document.getElementById("sysRxPktsBrief"),
  sysRxBar: document.getElementById("sysRxBar"),
  sysRxTotalVal: document.getElementById("sysRxTotalVal"),
  sysPrimaryIfaceRx: document.getElementById("sysPrimaryIfaceRx"),

  sysTxRateVal: document.getElementById("sysTxRateVal"),
  sysTxPktsBrief: document.getElementById("sysTxPktsBrief"),
  sysTxBar: document.getElementById("sysTxBar"),
  sysTxTotalVal: document.getElementById("sysTxTotalVal"),
  sysPrimaryIfaceTx: document.getElementById("sysPrimaryIfaceTx"),

  // Charts
  cpuRamCanvas: document.getElementById("cpuRamCanvas"),
  networkCanvas: document.getElementById("networkCanvas"),
  chartLegendCpu: document.getElementById("chartLegendCpu"),
  chartLegendRam: document.getElementById("chartLegendRam"),
  chartLegendRx: document.getElementById("chartLegendRx"),
  chartLegendTx: document.getElementById("chartLegendTx"),

  // Interfaces Table
  netInterfacesTable: document.getElementById("netInterfacesTable"),
  netInterfacesTableBody: document.getElementById("netInterfacesTableBody"),
  netIfaceCountBadge: document.getElementById("netIfaceCountBadge"),

  // Toast
  toastContainer: document.getElementById("toastContainer")
};

// ==========================================
// APPLICATION INITIALIZATION
// ==========================================
function initApp() {
  try { initTheme(); } catch (e) { console.error("initTheme error:", e); }
  try { setupEventListeners(); } catch (e) { console.error("setupEventListeners error:", e); }
  try { checkSystemStatus(); } catch (e) { console.error("checkSystemStatus error:", e); }

  // Khôi phục Tab đã mở trước đó
  try {
    const savedTab = localStorage.getItem("crowdsec_active_tab") || "tabDecisionsView";
    switchTab(savedTab);
  } catch (e) {
    console.error("switchTab error:", e);
  }

  // Tải dữ liệu ngay lập tức
  fetchDecisions();
  fetchScenarios();
  setupAutoRefresh();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}

// ==========================================
// EVENT LISTENERS SETUP
// ==========================================
function setupEventListeners() {
  // 1. Drawer Navigation (Menu 3 gạch)
  elements.hamburgerBtn.addEventListener("click", openDrawer);
  elements.sidebarCloseBtn.addEventListener("click", closeDrawer);
  elements.sidebarBackdrop.addEventListener("click", closeDrawer);

  elements.tabNavDecisions.addEventListener("click", () => {
    switchTab("tabDecisionsView");
    closeDrawer();
  });
  elements.tabNavScenarios.addEventListener("click", () => {
    switchTab("tabScenariosView");
    closeDrawer();
  });
  if (elements.tabNavSystem) {
    elements.tabNavSystem.addEventListener("click", () => {
      switchTab("tabSystemView");
      closeDrawer();
    });
  }

  // 2. Theme Toggle & Demo
  if (elements.themeToggleBtn) {
    elements.themeToggleBtn.addEventListener("click", toggleTheme);
  }
  if (elements.enableDemoBtn) {
    elements.enableDemoBtn.addEventListener("click", async () => {
      try {
        await fetch("/api/demo?action=enable");
        elements.permissionWarning.classList.add("hidden");
        elements.rootBadge.className = "status-pill status-nonroot";
        elements.rootBadgeText.textContent = "Chế độ Demo (Dữ liệu mẫu)";
        showToast("Đã bật Chế độ Demo thành công!", "info");
        await fetchDecisions(true);
        await fetchScenarios(true);
      } catch (e) {
        showToast("Không thể chuyển sang chế độ Demo", "error");
      }
    });
  }

  // 3. Navbar Dynamic Action Button
  elements.openAddModalBtn.addEventListener("click", () => {
    if (state.activeTab === "tabDecisionsView") {
      openAddModal();
    } else {
      openAddScenarioModal();
    }
  });

  // 4. Tab 1: Decisions Listeners
  elements.refreshBtn.addEventListener("click", () => fetchDecisions(true));
  elements.includeAllCheckbox.addEventListener("change", (e) => {
    state.includeAll = e.target.checked;
    elements.cliCommandHint.textContent = state.includeAll ? "cscli decisions list -a" : "cscli decisions list";
    fetchDecisions(true);
  });
  elements.searchInput.addEventListener("input", (e) => {
    state.searchQuery = e.target.value.trim().toLowerCase();
    elements.clearSearchBtn.classList.toggle("hidden", state.searchQuery === "");
    applyDecisionsFilterAndSort();
  });
  elements.clearSearchBtn.addEventListener("click", () => {
    elements.searchInput.value = "";
    state.searchQuery = "";
    elements.clearSearchBtn.classList.add("hidden");
    applyDecisionsFilterAndSort();
    elements.searchInput.focus();
  });
  elements.autoRefreshSelect.addEventListener("change", (e) => {
    state.autoRefreshInterval = parseInt(e.target.value, 10);
    setupAutoRefresh();
  });
  elements.decisionsTable.querySelectorAll("th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => {
      const col = th.getAttribute("data-sort");
      if (state.sortColumn === col) {
        state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
      } else {
        state.sortColumn = col;
        state.sortDirection = "desc";
      }
      applyDecisionsFilterAndSort();
    });
  });

  // Modal Add Decision
  elements.closeAddModalBtn.addEventListener("click", closeAddModal);
  elements.cancelAddBtn.addEventListener("click", closeAddModal);
  elements.addModal.addEventListener("click", (e) => {
    if (e.target === elements.addModal) closeAddModal();
  });
  [elements.targetInput, elements.durationInput, elements.typeSelect, elements.reasonInput].forEach((el) => {
    el.addEventListener("input", updateAddCliPreview);
    el.addEventListener("change", updateAddCliPreview);
  });
  elements.durationChips.querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      elements.durationChips.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      elements.durationInput.value = chip.getAttribute("data-val");
      updateAddCliPreview();
    });
  });
  elements.addDecisionForm.addEventListener("submit", handleAddDecision);

  // Modal Delete Decision
  elements.closeDeleteModalBtn.addEventListener("click", closeDeleteModal);
  elements.cancelDeleteBtn.addEventListener("click", closeDeleteModal);
  elements.deleteModal.addEventListener("click", (e) => {
    if (e.target === elements.deleteModal) closeDeleteModal();
  });
  elements.confirmDeleteBtn.addEventListener("click", handleConfirmDelete);

  // 5. Tab 2: Scenarios Listeners
  elements.refreshScenariosBtn.addEventListener("click", () => fetchScenarios(true));
  elements.openAddScenarioBtn.addEventListener("click", openAddScenarioModal);
  elements.scenarioIncludeAllCheckbox.addEventListener("change", (e) => {
    state.scenariosIncludeAll = e.target.checked;
    elements.cliScenarioCommandHint.textContent = state.scenariosIncludeAll ? "cscli scenarios list -a" : "cscli scenarios list";
    fetchScenarios(true);
  });
  elements.scenarioFilterSelect.addEventListener("change", (e) => {
    state.scenariosFilterType = e.target.value;
    applyScenariosFilterAndSort();
  });
  elements.scenarioSearchInput.addEventListener("input", (e) => {
    state.scenariosSearchQuery = e.target.value.trim().toLowerCase();
    elements.clearScenarioSearchBtn.classList.toggle("hidden", state.scenariosSearchQuery === "");
    applyScenariosFilterAndSort();
  });
  elements.clearScenarioSearchBtn.addEventListener("click", () => {
    elements.scenarioSearchInput.value = "";
    state.scenariosSearchQuery = "";
    elements.clearScenarioSearchBtn.classList.add("hidden");
    applyScenariosFilterAndSort();
    elements.scenarioSearchInput.focus();
  });
  elements.scenariosTable.querySelectorAll("th[data-sort-sc]").forEach((th) => {
    th.addEventListener("click", () => {
      const col = th.getAttribute("data-sort-sc");
      if (state.scenariosSortColumn === col) {
        state.scenariosSortDirection = state.scenariosSortDirection === "asc" ? "desc" : "asc";
      } else {
        state.scenariosSortColumn = col;
        state.scenariosSortDirection = "asc";
      }
      applyScenariosFilterAndSort();
    });
  });

  // Modal Add Scenario
  elements.closeAddScenarioModalBtn.addEventListener("click", closeAddScenarioModal);
  elements.cancelAddScenarioBtn.addEventListener("click", closeAddScenarioModal);
  elements.addScenarioModal.addEventListener("click", (e) => {
    if (e.target === elements.addScenarioModal) closeAddScenarioModal();
  });
  elements.scenarioFilenameInput.addEventListener("input", updateAddScenarioSavePathPreview);
  elements.addScenarioForm.addEventListener("submit", handleAddScenario);

  // Scenario Template Buttons
  document.querySelectorAll(".template-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tmpl = btn.getAttribute("data-template");
      if (SCENARIO_TEMPLATES[tmpl]) {
        elements.scenarioContentInput.value = SCENARIO_TEMPLATES[tmpl];
        showToast(`Đã nạp mẫu cấu hình ${tmpl.toUpperCase()}`, "info");
      }
    });
  });

  // Modal Edit Scenario
  elements.closeEditScenarioModalBtn.addEventListener("click", closeEditScenarioModal);
  elements.cancelEditScenarioBtn.addEventListener("click", closeEditScenarioModal);
  elements.editScenarioModal.addEventListener("click", (e) => {
    if (e.target === elements.editScenarioModal) closeEditScenarioModal();
  });
  elements.editScenarioForm.addEventListener("submit", handleSaveEditScenario);

  // Modal Delete Scenario
  elements.closeDeleteScenarioModalBtn.addEventListener("click", closeDeleteScenarioModal);
  elements.cancelDeleteScenarioBtn.addEventListener("click", closeDeleteScenarioModal);
  elements.deleteScenarioModal.addEventListener("click", (e) => {
    if (e.target === elements.deleteScenarioModal) closeDeleteScenarioModal();
  });
  elements.confirmDeleteScenarioBtn.addEventListener("click", handleConfirmDeleteScenario);

  // Phím Escape để đóng modals / drawer
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeDrawer();
      closeAddModal();
      closeDeleteModal();
      closeAddScenarioModal();
      closeEditScenarioModal();
      closeDeleteScenarioModal();
    }
  });

  // 5. Tab 3: System Metrics Listeners
  if (elements.sysIfaceSelect) {
    elements.sysIfaceSelect.addEventListener("change", (e) => {
      state.system.selectedInterface = e.target.value;
      state.system.history.rx = [];
      state.system.history.tx = [];
      state.system.history.cpu = [];
      state.system.history.ram = [];
      state.system.history.labels = [];
      if (state.system.lastData) {
        updateSystemDashboard(state.system.lastData);
      }
    });
  }

  if (elements.sysRefreshIntervalSelect) {
    elements.sysRefreshIntervalSelect.addEventListener("change", (e) => {
      state.system.pollInterval = parseInt(e.target.value, 10) || 2000;
      if (!state.system.isPaused && state.activeTab === "tabSystemView") {
        startSystemMetricsTimer();
      }
    });
  }

  if (elements.sysPauseResumeBtn) {
    elements.sysPauseResumeBtn.addEventListener("click", toggleSystemMetricsPause);
  }

  if (elements.sysRefreshOnceBtn) {
    elements.sysRefreshOnceBtn.addEventListener("click", () => {
      fetchSystemMetrics(true);
    });
  }

  window.addEventListener("resize", () => {
    if (state.activeTab === "tabSystemView") {
      renderSystemCharts();
    }
  });
}

// ==========================================
// DRAWER & TAB MANAGEMENT
// ==========================================
function openDrawer() {
  elements.sidebarDrawer.classList.add("open");
  elements.sidebarBackdrop.classList.remove("hidden");
}

function closeDrawer() {
  elements.sidebarDrawer.classList.remove("open");
  elements.sidebarBackdrop.classList.add("hidden");
}

function switchTab(tabId) {
  state.activeTab = tabId;
  localStorage.setItem("crowdsec_active_tab", tabId);

  // Cập nhật giao diện menu
  if (elements.tabNavDecisions) elements.tabNavDecisions.classList.toggle("active", tabId === "tabDecisionsView");
  if (elements.tabNavScenarios) elements.tabNavScenarios.classList.toggle("active", tabId === "tabScenariosView");
  if (elements.tabNavSystem) elements.tabNavSystem.classList.toggle("active", tabId === "tabSystemView");

  // Chuyển view
  if (elements.tabDecisionsView) {
    elements.tabDecisionsView.classList.toggle("hidden", tabId !== "tabDecisionsView");
    elements.tabDecisionsView.classList.toggle("active", tabId === "tabDecisionsView");
  }
  if (elements.tabScenariosView) {
    elements.tabScenariosView.classList.toggle("hidden", tabId !== "tabScenariosView");
    elements.tabScenariosView.classList.toggle("active", tabId === "tabScenariosView");
  }
  if (elements.tabSystemView) {
    elements.tabSystemView.classList.toggle("hidden", tabId !== "tabSystemView");
    elements.tabSystemView.classList.toggle("active", tabId === "tabSystemView");
  }

  // Cập nhật Header & Action button theo Tab
  if (tabId === "tabDecisionsView") {
    if (elements.pageTitle) elements.pageTitle.textContent = "CrowdSec Decisions";
    if (elements.pageSubtitle) elements.pageSubtitle.textContent = "Quản trị danh sách IP bị chặn & Phòng thủ máy chủ";
    if (elements.openAddModalBtn) elements.openAddModalBtn.classList.remove("hidden");
    if (elements.openAddModalText) elements.openAddModalText.textContent = "Thêm IP Chặn";
    stopSystemMetricsTimer();
  } else if (tabId === "tabScenariosView") {
    if (elements.pageTitle) elements.pageTitle.textContent = "CrowdSec Scenarios";
    if (elements.pageSubtitle) elements.pageSubtitle.textContent = "Quản trị kịch bản phát hiện (/etc/crowdsec/scenarios/)";
    if (elements.openAddModalBtn) elements.openAddModalBtn.classList.remove("hidden");
    if (elements.openAddModalText) elements.openAddModalText.textContent = "Thêm Scenario";

    if (state.scenarios.length === 0) {
      fetchScenarios();
    }
    stopSystemMetricsTimer();
  } else if (tabId === "tabSystemView") {
    if (elements.pageTitle) elements.pageTitle.textContent = "Giám Sát Hệ Thống";
    if (elements.pageSubtitle) elements.pageSubtitle.textContent = "Theo dõi CPU, RAM và lưu lượng mạng trực tiếp theo thời gian thực";
    if (elements.openAddModalBtn) elements.openAddModalBtn.classList.add("hidden");

    fetchSystemMetrics(true);
    startSystemMetricsTimer();
    setTimeout(() => {
      renderSystemCharts();
    }, 50);
  }
}

// ==========================================
// SYSTEM STATUS CHECK
// ==========================================
async function checkSystemStatus() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();

    if (data.is_root) {
      elements.rootBadge.className = "status-pill status-root";
      elements.rootBadgeText.textContent = "Root Mode (cscli Sẵn sàng)";
      elements.permissionWarning.classList.add("hidden");
    } else {
      elements.rootBadge.className = "status-pill status-nonroot";
      elements.rootBadgeText.textContent = "Người dùng: " + (data.user || "non-root");
      elements.permissionWarning.classList.remove("hidden");
    }
  } catch (err) {
    elements.rootBadge.className = "status-pill status-unknown";
    elements.rootBadgeText.textContent = "Mất kết nối API";
  }
}

// ==========================================
// TAB 1: DECISIONS LOGIC
// ==========================================
async function fetchDecisions(isManual = false) {
  if (state.isLoadingDecisions) return;
  state.isLoadingDecisions = true;

  if (isManual) elements.refreshIcon.classList.add("spinning");

  try {
    const url = `/api/decisions?all=${state.includeAll}`;
    const res = await fetch(url);
    const data = await res.json();

    if (data.status === "success") {
      state.decisions = data.decisions || [];
      if (data.demo_mode) {
        elements.rootBadge.className = "status-pill status-nonroot";
        elements.rootBadgeText.textContent = "Chế độ Demo (Dữ liệu mẫu)";
        elements.permissionWarning.classList.add("hidden");
      }
      updateDecisionsStatistics();
      applyDecisionsFilterAndSort();
      if (!data.demo_mode && data.is_root) {
        elements.permissionWarning.classList.add("hidden");
      }
    } else {
      showToast(data.message || "Không thể lấy danh sách quyết định", "error");
      if (!data.is_root) elements.permissionWarning.classList.remove("hidden");
      renderDecisionsError(data.message || "Không thể lấy danh sách quyết định");
    }
  } catch (err) {
    console.error("Lỗi khi tải decisions:", err);
    showToast("Lỗi kết nối tới CrowdSec Backend API", "error");
    renderDecisionsError("Lỗi kết nối tới Backend API. Vui lòng bấm 'Làm mới' để thử lại.");
  } finally {
    state.isLoadingDecisions = false;
    elements.refreshIcon.classList.remove("spinning");
    state.lastUpdated = new Date();
    elements.statLastUpdated.textContent = state.lastUpdated.toLocaleTimeString("vi-VN");
  }
}

function updateDecisionsStatistics() {
  const total = state.decisions.length;
  let localCount = 0;
  let capiCount = 0;

  state.decisions.forEach((d) => {
    const src = (d.source || "").toLowerCase();
    if (src === "capi" || src.includes("community")) {
      capiCount++;
    } else {
      localCount++;
    }
  });

  elements.statTotalBans.textContent = total.toLocaleString();
  elements.statLocalBans.textContent = localCount.toLocaleString();
  elements.statCapiBans.textContent = capiCount.toLocaleString();
  elements.badgeDecisionsCount.textContent = total.toLocaleString();
}

function applyDecisionsFilterAndSort() {
  let list = [...state.decisions];

  if (state.searchQuery) {
    const q = state.searchQuery;
    list = list.filter((item) => {
      return (
        (item.value && item.value.toLowerCase().includes(q)) ||
        (item.scope_value && item.scope_value.toLowerCase().includes(q)) ||
        (item.reason && item.reason.toLowerCase().includes(q)) ||
        (item.source && item.source.toLowerCase().includes(q)) ||
        (item.country && item.country.toLowerCase().includes(q)) ||
        (item.as && item.as.toLowerCase().includes(q)) ||
        (item.id && String(item.id).includes(q)) ||
        (item.alert_id && String(item.alert_id).includes(q))
      );
    });
  }

  list.sort((a, b) => {
    let valA = a[state.sortColumn] || "";
    let valB = b[state.sortColumn] || "";

    if (["id", "alert_id", "events"].includes(state.sortColumn)) {
      valA = parseInt(valA, 10) || 0;
      valB = parseInt(valB, 10) || 0;
    }

    if (valA < valB) return state.sortDirection === "asc" ? -1 : 1;
    if (valA > valB) return state.sortDirection === "asc" ? 1 : -1;
    return 0;
  });

  state.filteredDecisions = list;
  renderDecisionsTable();
}

function renderDecisionsTable() {
  const tbody = elements.decisionsTableBody;
  const list = state.filteredDecisions;

  elements.rowCountBadge.textContent = `${list.length} mục`;

  if (state.searchQuery) {
    elements.filterResultText.textContent = `Tìm thấy ${list.length} / ${state.decisions.length} quyết định phù hợp`;
  } else {
    elements.filterResultText.textContent = `Hiển thị ${list.length} quyết định đang có hiệu lực`;
  }

  if (list.length === 0) {
    if (state.decisions.length === 0) {
      tbody.innerHTML = `
        <tr class="empty-row">
          <td colspan="11">
            <div class="empty-state">
              <span class="empty-title">Không có IP nào đang bị chặn</span>
              <span class="empty-desc">Hệ thống an toàn hoặc danh sách quyết định rỗng. Nhấn "Thêm IP Chặn" để chặn thủ công.</span>
            </div>
          </td>
        </tr>
      `;
    } else {
      tbody.innerHTML = `
        <tr class="empty-row">
          <td colspan="11">
            <div class="empty-state">
              <span class="empty-icon">🔍</span>
              <span class="empty-title">Không tìm thấy kết quả</span>
              <span class="empty-desc">Không có IP hoặc lý do nào khớp với từ khóa "${escapeHtml(state.searchQuery)}".</span>
            </div>
          </td>
        </tr>
      `;
    }
    return;
  }

  tbody.innerHTML = list.map((item, index) => {
    const sourceClass = getSourceBadgeClass(item.source);
    const actionClass = getActionBadgeClass(item.action);
    let ipValue = item.value || "";
    if (!ipValue && item.scope_value) {
      ipValue = item.scope_value.includes(":") ? item.scope_value.split(":")[1] : item.scope_value;
    }
    if (ipValue && /^(ip|range):/i.test(ipValue)) {
      ipValue = ipValue.replace(/^(ip|range):/i, "").trim();
    }

    return `
      <tr data-id="${escapeHtml(item.id)}" data-index="${index}">
        <td class="font-mono">${escapeHtml(item.id || "-")}</td>
        <td>
          <span class="source-badge ${sourceClass}">${escapeHtml(item.source || "crowdsec")}</span>
        </td>
        <td>
          <div class="ip-cell">
            <span class="ip-text">${escapeHtml(item.scope_value || item.value || "-")}</span>
            <button class="copy-ip-btn" title="Copy IP" onclick="copyToClipboard('${escapeHtml(ipValue)}')">
              <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" stroke-width="2" fill="none">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
            </button>
          </div>
        </td>
        <td>
          <div class="reason-cell" title="${escapeHtml(item.reason || "-")}">
            ${escapeHtml(item.reason || "-")}
          </div>
        </td>
        <td>
          <span class="action-badge ${actionClass}">${escapeHtml(item.action || "ban")}</span>
        </td>
        <td>
          <span class="country-flag">${renderCountry(item.country)}</span>
        </td>
        <td>${escapeHtml(item.as || "-")}</td>
        <td class="font-mono">${escapeHtml(item.events || "-")}</td>
        <td class="font-mono text-muted">${escapeHtml(item.expiration || "-")}</td>
        <td class="font-mono">${escapeHtml(item.alert_id || "-")}</td>
        <td class="text-center">
          <button 
            class="btn-delete" 
            title="Xóa chặn IP này (cscli decisions delete ${ipValue.includes('/') ? '-r' : '-i'} ${escapeHtml(ipValue)})"
            onclick="promptDeleteByIndex(${index})"
          >
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="3 6 5 6 21 6"></polyline>
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
              <line x1="10" y1="11" x2="10" y2="17"></line>
              <line x1="14" y1="11" x2="14" y2="17"></line>
            </svg>
            <span>Xóa</span>
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

function renderDecisionsError(msg) {
  if (state.decisions.length === 0 && elements.decisionsTableBody) {
    elements.decisionsTableBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="11">
          <div class="empty-state">
            <span class="empty-icon">⚠️</span>
            <span class="empty-title">Không thể tải danh sách IP</span>
            <span class="empty-desc">${escapeHtml(msg)}</span>
            <button class="btn btn-secondary btn-sm" style="margin-top: 10px;" onclick="fetchDecisions(true)">Thử lại</button>
          </div>
        </td>
      </tr>
    `;
  }
}

// Add/Delete Decision Modals
function openAddModal() {
  elements.targetInput.value = "";
  elements.durationInput.value = "4h";
  elements.reasonInput.value = "manual-ban-web";
  elements.typeSelect.value = "ban";
  elements.durationChips.querySelectorAll(".chip").forEach((c) => {
    c.classList.toggle("active", c.getAttribute("data-val") === "4h");
  });
  updateAddCliPreview();
  elements.addModal.classList.remove("hidden");
  setTimeout(() => elements.targetInput.focus(), 50);
}

function closeAddModal() {
  elements.addModal.classList.add("hidden");
}

function updateAddCliPreview() {
  const target = elements.targetInput.value.trim() || "<IP/Dải_Mạng>";
  const duration = elements.durationInput.value.trim() || "4h";
  const reason = elements.reasonInput.value.trim() || "manual-ban";
  const type = elements.typeSelect.value || "ban";
  const isRange = target.includes("/");
  const flag = isRange ? "-r" : "-i";
  elements.cliAddPreview.textContent = `cscli decisions add ${flag} ${target} -d ${duration} -R "${reason}" -t ${type}`;
}

async function handleAddDecision(e) {
  e.preventDefault();
  const target = elements.targetInput.value.trim();
  const duration = elements.durationInput.value.trim() || "4h";
  const reason = elements.reasonInput.value.trim() || "manual-ban";
  const type = elements.typeSelect.value || "ban";

  if (!target) {
    showToast("Vui lòng nhập địa chỉ IP hoặc dải mạng cần chặn", "error");
    elements.targetInput.focus();
    return;
  }

  const submitBtn = elements.submitAddBtn;
  const btnText = submitBtn.querySelector(".btn-text");
  const spinner = submitBtn.querySelector(".btn-spinner");
  submitBtn.disabled = true;
  btnText.textContent = "Đang thực thi...";
  spinner.classList.remove("hidden");

  try {
    const res = await fetch("/api/decisions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip: target, duration, reason, type })
    });
    const data = await res.json();
    if (res.ok && data.status === "success") {
      showToast(`Đã thêm thành công lệnh chặn cho ${target}!`, "success");
      closeAddModal();
      await fetchDecisions(true);
    } else {
      showToast(data.message || "Không thể thêm quyết định chặn", "error");
    }
  } catch (err) {
    showToast("Lỗi kết nối khi gửi yêu cầu chặn IP", "error");
  } finally {
    submitBtn.disabled = false;
    btnText.textContent = "Xác nhận chặn";
    spinner.classList.add("hidden");
  }
}

window.promptDeleteByIndex = function (index) {
  const item = state.filteredDecisions ? state.filteredDecisions[index] : null;
  if (!item) return;
  let ip = item.value || "";
  if (!ip && item.scope_value) {
    ip = item.scope_value.includes(":") ? item.scope_value.split(":")[1] : item.scope_value;
  }
  if (ip && /^(ip|range):/i.test(ip)) {
    ip = ip.replace(/^(ip|range):/i, "").trim();
  }
  promptDelete(item.id, ip, item.reason || "");
};

window.promptDelete = function (id, ip, reason) {
  state.selectedForDelete = { id, ip, reason };
  elements.deleteTargetValue.textContent = ip || `ID: ${id}`;
  elements.deleteTargetReason.textContent = reason || "-";
  elements.deleteTargetId.textContent = (id && id !== "-") ? id : "-";
  if (id && id !== "-" && String(id).trim().match(/^\d+$/)) {
    elements.cliDeletePreview.textContent = `cscli decisions delete --id ${id}`;
  } else if (ip) {
    const isRange = ip.includes("/");
    const flag = isRange ? "-r" : "-i";
    elements.cliDeletePreview.textContent = `cscli decisions delete ${flag} ${ip}`;
  } else {
    elements.cliDeletePreview.textContent = `cscli decisions delete`;
  }
  elements.deleteModal.classList.remove("hidden");
};

function closeDeleteModal() {
  elements.deleteModal.classList.add("hidden");
  state.selectedForDelete = null;
}

async function handleConfirmDelete() {
  if (!state.selectedForDelete) return;
  const { id, ip } = state.selectedForDelete;
  const confirmBtn = elements.confirmDeleteBtn;
  const btnText = confirmBtn.querySelector(".btn-text");
  const spinner = confirmBtn.querySelector(".btn-spinner");

  confirmBtn.disabled = true;
  btnText.textContent = "Đang xóa...";
  spinner.classList.remove("hidden");

  try {
    const params = new URLSearchParams();
    if (ip) params.set("ip", ip);
    if (id && id !== "-" && String(id).trim().match(/^\d+$/)) params.set("id", id);

    const res = await fetch(`/api/decisions?${params.toString()}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" }
    });
    const data = await res.json();
    if (res.ok && data.status === "success") {
      showToast(`Đã xóa thành công quyết định đối với ${ip || ("ID: " + id)}!`, "success");
      closeDeleteModal();
      await fetchDecisions(true);
    } else {
      showToast(data.message || "Không thể xóa quyết định chặn", "error");
    }
  } catch (err) {
    showToast("Lỗi kết nối khi gửi yêu cầu xóa IP", "error");
  } finally {
    confirmBtn.disabled = false;
    btnText.textContent = "Xóa IP ngay";
    spinner.classList.add("hidden");
  }
}

// ==========================================
// TAB 2: SCENARIOS LOGIC
// ==========================================
async function fetchScenarios(isManual = false) {
  if (state.isLoadingScenarios) return;
  state.isLoadingScenarios = true;

  if (isManual) elements.refreshScenariosIcon.classList.add("spinning");

  try {
    const res = await fetch(`/api/scenarios?all=${state.scenariosIncludeAll}`);
    const data = await res.json();

    if (data.status === "success") {
      state.scenarios = data.scenarios || [];
      updateScenariosStatistics();
      applyScenariosFilterAndSort();
    } else {
      showToast(data.message || "Không thể lấy danh sách scenarios", "error");
      renderScenariosError(data.message || "Không thể lấy danh sách scenarios");
    }
  } catch (err) {
    console.error("Lỗi khi tải scenarios:", err);
    showToast("Lỗi kết nối khi tải danh sách scenarios", "error");
    renderScenariosError("Lỗi kết nối khi tải danh sách scenarios. Vui lòng bấm 'Làm mới' để thử lại.");
  } finally {
    state.isLoadingScenarios = false;
    elements.refreshScenariosIcon.classList.remove("spinning");
  }
}

function updateScenariosStatistics() {
  let total = state.scenarios.length;
  let enabledCount = 0;
  let disabledCount = 0;
  let localCount = 0;

  state.scenarios.forEach((sc) => {
    if (sc.status === "enabled") enabledCount++;
    else disabledCount++;
    if (sc.type === "Local" || sc.is_custom) localCount++;
  });

  elements.statScenariosTotal.textContent = total.toLocaleString();
  elements.statScenariosEnabled.textContent = enabledCount.toLocaleString();
  elements.statScenariosDisabled.textContent = disabledCount.toLocaleString();
  elements.statScenariosLocal.textContent = localCount.toLocaleString();
  elements.badgeScenariosCount.textContent = enabledCount.toLocaleString();
}

function applyScenariosFilterAndSort() {
  let list = [...state.scenarios];

  // 1. Lọc theo dropdown Type / Status
  if (state.scenariosFilterType === "enabled") {
    list = list.filter((s) => s.status === "enabled");
  } else if (state.scenariosFilterType === "disabled") {
    list = list.filter((s) => s.status === "disabled");
  } else if (state.scenariosFilterType === "local") {
    list = list.filter((s) => s.type === "Local" || s.is_custom);
  } else if (state.scenariosFilterType === "hub") {
    list = list.filter((s) => s.type === "Hub" && !s.is_custom);
  }

  // 2. Lọc theo ô tìm kiếm
  if (state.scenariosSearchQuery) {
    const q = state.scenariosSearchQuery;
    list = list.filter((s) => {
      return (
        (s.name && s.name.toLowerCase().includes(q)) ||
        (s.description && s.description.toLowerCase().includes(q)) ||
        (s.filename && s.filename.toLowerCase().includes(q)) ||
        (s.path && s.path.toLowerCase().includes(q)) ||
        (s.type && s.type.toLowerCase().includes(q))
      );
    });
  }

  // 3. Sắp xếp cột
  list.sort((a, b) => {
    let valA = a[state.scenariosSortColumn] || "";
    let valB = b[state.scenariosSortColumn] || "";
    if (valA < valB) return state.scenariosSortDirection === "asc" ? -1 : 1;
    if (valA > valB) return state.scenariosSortDirection === "asc" ? 1 : -1;
    return 0;
  });

  state.filteredScenarios = list;
  renderScenariosTable();
}

function renderScenariosTable() {
  const tbody = elements.scenariosTableBody;
  const list = state.filteredScenarios;

  elements.scenariosCountBadge.textContent = `${list.length} mục`;
  elements.scenariosFilterResultText.textContent = `Hiển thị ${list.length} / ${state.scenarios.length} kịch bản`;

  if (list.length === 0) {
    tbody.innerHTML = `
      <tr class="empty-row">
        <td colspan="6">
          <div class="empty-state">
            <span class="empty-icon">📜</span>
            <span class="empty-title">Không tìm thấy Scenario nào</span>
            <span class="empty-desc">Thử thay đổi bộ lọc hoặc bấm "Thêm Scenario Mới" để tạo kịch bản bảo vệ.</span>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = list.map((sc) => {
    const isEnabled = sc.status === "enabled";
    const isLocal = sc.type === "Local" || sc.is_custom;
    const typeBadgeClass = isLocal ? "type-badge-local" : "type-badge-hub";
    const statusDotClass = isEnabled ? "legend-dot green" : "legend-dot red";

    return `
      <tr>
        <td>
          <div style="font-weight: 600; color: var(--text-heading); cursor: pointer;" onclick="openEditScenarioModal('${escapeHtml(sc.path)}', '${escapeHtml(sc.name)}', '${isLocal ? "Local" : "Hub"}')">
            ${escapeHtml(sc.name)}
          </div>
        </td>
        <td>
          <span class="source-badge ${typeBadgeClass}">${escapeHtml(sc.type || (isLocal ? "Local" : "Hub"))}</span>
        </td>
        <td>
          <span style="display:inline-flex; align-items:center; gap:0.4rem; font-weight:600; font-size:0.8rem;">
            <span class="${statusDotClass}"></span>
            <span style="color: ${isEnabled ? 'var(--accent-success)' : 'var(--text-muted)'};">${isEnabled ? 'Enabled' : 'Disabled'}</span>
          </span>
        </td>
        <td>
          <div class="reason-cell" title="${escapeHtml(sc.description || "-")}">
            ${escapeHtml(sc.description || "-")}
          </div>
        </td>
        <td class="font-mono text-muted" style="font-size:0.775rem;">
          ${escapeHtml(sc.path || sc.filename || "-")}
        </td>
        <td class="text-center">
          <div class="scenario-actions-cell">
            <!-- Nút Bật / Tắt -->
            ${isEnabled ? `
              <button 
                class="btn-toggle-disable" 
                title="Tắt kịch bản này"
                onclick="handleScenarioToggle('${escapeHtml(sc.name)}', '${escapeHtml(sc.path)}', 'disable', ${isLocal})"
              >
                <span>Tắt</span>
              </button>
            ` : `
              <button 
                class="btn-toggle-enable" 
                title="Bật kịch bản này"
                onclick="handleScenarioToggle('${escapeHtml(sc.name)}', '${escapeHtml(sc.path)}', 'enable', ${isLocal})"
              >
                <span>Bật</span>
              </button>
            `}

            <!-- Nút Chỉnh sửa -->
            <button 
              class="btn-edit" 
              title="Chỉnh sửa nội dung YAML kịch bản"
              onclick="openEditScenarioModal('${escapeHtml(sc.path)}', '${escapeHtml(sc.name)}', '${isLocal ? "Local" : "Hub"}')"
            >
              <span>Sửa</span>
            </button>

            <!-- Nút Xóa -->
            <button 
              class="btn-delete" 
              title="Xóa kịch bản"
              onclick="promptDeleteScenario('${escapeHtml(sc.name)}', '${escapeHtml(sc.path)}', '${isLocal ? "Local" : "Hub"}')"
            >
              <span>Xóa</span>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

function renderScenariosError(msg) {
  if (state.scenarios.length === 0 && elements.scenariosTableBody) {
    elements.scenariosTableBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="6">
          <div class="empty-state">
            <span class="empty-icon">⚠️</span>
            <span class="empty-title">Không thể tải danh sách Scenarios</span>
            <span class="empty-desc">${escapeHtml(msg)}</span>
            <button class="btn btn-secondary btn-sm" style="margin-top: 10px;" onclick="fetchScenarios(true)">Thử lại</button>
          </div>
        </td>
      </tr>
    `;
  }
}

// Bật / Tắt Scenario
window.handleScenarioToggle = async function (name, path, action, isCustom) {
  const actionText = action === "enable" ? "bật" : "tắt";
  showToast(`Đang ${actionText} kịch bản ${name}...`, "info");

  try {
    const res = await fetch("/api/scenarios/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, path, action, is_custom: Boolean(isCustom) })
    });
    const data = await res.json();
    if (res.ok && data.status === "success") {
      showToast(data.message || `Đã ${actionText} kịch bản thành công!`, "success");
      await fetchScenarios(true);
    } else {
      showToast(data.message || `Không thể ${actionText} kịch bản`, "error");
    }
  } catch (err) {
    showToast(`Lỗi kết nối khi gửi lệnh ${actionText} kịch bản`, "error");
  }
};

// Thêm Scenario Modal
function openAddScenarioModal() {
  elements.scenarioFilenameInput.value = "";
  elements.scenarioContentInput.value = SCENARIO_TEMPLATES.leaky;
  updateAddScenarioSavePathPreview();
  elements.addScenarioModal.classList.remove("hidden");
  setTimeout(() => elements.scenarioFilenameInput.focus(), 50);
}

function closeAddScenarioModal() {
  elements.addScenarioModal.classList.add("hidden");
}

function updateAddScenarioSavePathPreview() {
  let name = elements.scenarioFilenameInput.value.trim() || "<tên-file>";
  name = name.replace(/[^a-zA-Z0-9_\-\.]/g, "");
  if (!name.endsWith(".yml") && !name.endsWith(".yaml") && name !== "<tên-file>") {
    name += ".yml";
  }
  elements.previewSavePath.textContent = `/etc/crowdsec/scenarios/${name}`;
}

async function handleAddScenario(e) {
  e.preventDefault();
  let filename = elements.scenarioFilenameInput.value.trim();
  const content = elements.scenarioContentInput.value.trim();

  if (!filename) {
    showToast("Vui lòng nhập tên file scenario", "error");
    elements.scenarioFilenameInput.focus();
    return;
  }
  if (!content) {
    showToast("Nội dung cấu hình YAML không được để trống", "error");
    elements.scenarioContentInput.focus();
    return;
  }

  const submitBtn = elements.submitAddScenarioBtn;
  const btnText = submitBtn.querySelector(".btn-text");
  const spinner = submitBtn.querySelector(".btn-spinner");
  submitBtn.disabled = true;
  btnText.textContent = "Đang lưu...";
  spinner.classList.remove("hidden");

  try {
    const res = await fetch("/api/scenarios", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename, content })
    });
    const data = await res.json();
    if (res.ok && data.status === "success") {
      showToast(data.message || "Đã lưu kịch bản thành công!", "success");
      closeAddScenarioModal();
      await fetchScenarios(true);
    } else {
      showToast(data.message || "Không thể lưu kịch bản", "error");
    }
  } catch (err) {
    showToast("Lỗi kết nối khi gửi kịch bản", "error");
  } finally {
    submitBtn.disabled = false;
    btnText.textContent = "Lưu Scenario (.yml)";
    spinner.classList.add("hidden");
  }
}

// Chỉnh sửa Scenario Modal
window.openEditScenarioModal = async function (path, name, type) {
  state.selectedScenarioForEdit = { path, name, type };
  elements.editModalTitle.textContent = `Chỉnh Sửa Scenario: ${name}`;
  elements.editModalSubtitle.textContent = path || "/etc/crowdsec/scenarios/...";
  elements.editScenarioNameText.textContent = name;
  elements.editScenarioTypeText.textContent = type;
  elements.editScenarioContentInput.value = "Đang tải nội dung file từ hệ thống...";
  elements.editScenarioModal.classList.remove("hidden");

  try {
    const res = await fetch(`/api/scenarios/content?path=${encodeURIComponent(path)}`);
    const data = await res.json();
    if (res.ok && data.status === "success") {
      elements.editScenarioContentInput.value = data.content || "";
    } else {
      elements.editScenarioContentInput.value = `# Không thể đọc nội dung: ${data.message}`;
      showToast(data.message || "Lỗi khi đọc file kịch bản", "error");
    }
  } catch (err) {
    elements.editScenarioContentInput.value = "# Lỗi kết nối khi đọc file kịch bản";
    showToast("Lỗi kết nối khi đọc file", "error");
  }
};

function closeEditScenarioModal() {
  elements.editScenarioModal.classList.add("hidden");
  state.selectedScenarioForEdit = null;
}

async function handleSaveEditScenario(e) {
  e.preventDefault();
  if (!state.selectedScenarioForEdit) return;

  const { path } = state.selectedScenarioForEdit;
  const content = elements.editScenarioContentInput.value;

  const submitBtn = elements.submitEditScenarioBtn;
  const btnText = submitBtn.querySelector(".btn-text");
  const spinner = submitBtn.querySelector(".btn-spinner");
  submitBtn.disabled = true;
  btnText.textContent = "Đang lưu thay đổi...";
  spinner.classList.remove("hidden");

  try {
    const res = await fetch("/api/scenarios", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, content })
    });
    const data = await res.json();
    if (res.ok && data.status === "success") {
      showToast(data.message || "Đã cập nhật kịch bản thành công!", "success");
      closeEditScenarioModal();
      await fetchScenarios(true);
    } else {
      showToast(data.message || "Lỗi khi lưu cập nhật kịch bản", "error");
    }
  } catch (err) {
    showToast("Lỗi kết nối khi lưu kịch bản", "error");
  } finally {
    submitBtn.disabled = false;
    btnText.textContent = "Lưu Thay Đổi";
    spinner.classList.add("hidden");
  }
}

// Xóa Scenario Modal
window.promptDeleteScenario = function (name, path, type) {
  state.selectedScenarioForDelete = { name, path, type };
  elements.deleteScenarioName.textContent = name;
  elements.deleteScenarioType.textContent = type;
  elements.deleteScenarioPath.textContent = path || "-";

  if (type === "Hub") {
    elements.cliScenarioDeletePreview.textContent = `cscli scenarios remove ${name} --purge`;
  } else {
    elements.cliScenarioDeletePreview.textContent = `rm -f ${path}`;
  }

  elements.deleteScenarioModal.classList.remove("hidden");
};

function closeDeleteScenarioModal() {
  elements.deleteScenarioModal.classList.add("hidden");
  state.selectedScenarioForDelete = null;
}

async function handleConfirmDeleteScenario() {
  if (!state.selectedScenarioForDelete) return;

  const { name, path, type } = state.selectedScenarioForDelete;
  const isCustom = (type === "Local");
  const confirmBtn = elements.confirmDeleteScenarioBtn;
  const btnText = confirmBtn.querySelector(".btn-text");
  const spinner = confirmBtn.querySelector(".btn-spinner");
  confirmBtn.disabled = true;
  btnText.textContent = "Đang xóa...";
  spinner.classList.remove("hidden");

  try {
    const res = await fetch("/api/scenarios/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, path, action: "delete", is_custom: isCustom })
    });
    const data = await res.json();
    if (res.ok && data.status === "success") {
      showToast(data.message || `Đã xóa kịch bản ${name} thành công!`, "success");
      closeDeleteScenarioModal();
      await fetchScenarios(true);
    } else {
      showToast(data.message || "Lỗi khi xóa kịch bản", "error");
    }
  } catch (err) {
    showToast("Lỗi kết nối khi xóa kịch bản", "error");
  } finally {
    confirmBtn.disabled = false;
    btnText.textContent = "Xác Nhận Xóa";
    spinner.classList.add("hidden");
  }
}

// ==========================================
// HELPERS, THEME & UTILITIES
// ==========================================
function setupAutoRefresh() {
  if (state.timerId) {
    clearInterval(state.timerId);
    state.timerId = null;
  }
  if (state.autoRefreshInterval > 0) {
    elements.statRefreshInterval.textContent = `Tự động làm mới: ${state.autoRefreshInterval} giây`;
    state.timerId = setInterval(() => {
      fetchDecisions(false);
      if (state.activeTab === "tabScenariosView") {
        fetchScenarios(false);
      }
    }, state.autoRefreshInterval * 1000);
  } else {
    elements.statRefreshInterval.textContent = "Tự động làm mới: Đã tắt";
  }
}

function initTheme() {
  const savedTheme = localStorage.getItem("crowdsec_theme");
  const systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const currentTheme = savedTheme || (systemDark ? "dark" : "light");
  applyTheme(currentTheme, false);

  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
    if (!localStorage.getItem("crowdsec_theme")) {
      applyTheme(e.matches ? "dark" : "light", false);
    }
  });
}

function applyTheme(theme, notify = true) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("crowdsec_theme", theme);
  if (elements.themeToggleText) {
    elements.themeToggleText.textContent = theme === "dark" ? "Chế độ tối" : "Chế độ sáng";
  }
  if (elements.themeToggleBtn) {
    elements.themeToggleBtn.setAttribute(
      "title",
      theme === "dark" ? "Chuyển sang Giao diện Sáng (Light Mode)" : "Chuyển sang Giao diện Tối (Dark Mode)"
    );
  }
  if (notify) {
    showToast(theme === "dark" ? "Đã chuyển sang Giao diện Tối 🌙" : "Đã chuyển sang Giao diện Sáng ☀️", "info");
  }
  if (state.activeTab === "tabSystemView") {
    renderSystemCharts();
  }
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
  const newTheme = currentTheme === "dark" ? "light" : "dark";
  applyTheme(newTheme, true);
}

// ==========================================
// TAB 3: REAL-TIME SYSTEM MONITORING LOGIC
// ==========================================

function startSystemMetricsTimer() {
  stopSystemMetricsTimer();
  if (state.system.isPaused) return;
  state.system.timerId = setInterval(() => {
    if (state.activeTab === "tabSystemView" && !state.system.isPaused) {
      fetchSystemMetrics();
    }
  }, state.system.pollInterval);
}

function stopSystemMetricsTimer() {
  if (state.system.timerId) {
    clearInterval(state.system.timerId);
    state.system.timerId = null;
  }
}

function toggleSystemMetricsPause() {
  state.system.isPaused = !state.system.isPaused;
  if (state.system.isPaused) {
    stopSystemMetricsTimer();
    if (elements.sysPauseResumeIcon) elements.sysPauseResumeIcon.textContent = "▶️";
    if (elements.sysPauseResumeText) elements.sysPauseResumeText.textContent = "Tiếp tục";
    if (elements.sysLiveStatusText) elements.sysLiveStatusText.textContent = "Đã tạm dừng";
    showToast("Đã tạm dừng cập nhật biểu đồ", "info");
  } else {
    startSystemMetricsTimer();
    if (elements.sysPauseResumeIcon) elements.sysPauseResumeIcon.textContent = "⏸️";
    if (elements.sysPauseResumeText) elements.sysPauseResumeText.textContent = "Tạm dừng";
    if (elements.sysLiveStatusText) elements.sysLiveStatusText.textContent = "Đang theo dõi trực tiếp";
    fetchSystemMetrics(true);
    showToast("Tiếp tục cập nhật trực tiếp", "info");
  }
}

async function fetchSystemMetrics(isManual = false) {
  if (state.system.isLoading && !isManual) return;
  state.system.isLoading = true;

  try {
    const res = await fetch("/api/system/metrics");
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    if (data.status !== "success") throw new Error(data.message || "Lỗi đọc dữ liệu");

    state.system.lastData = data;
    updateSystemDashboard(data);
  } catch (err) {
    console.error("fetchSystemMetrics error:", err);
    if (isManual) {
      showToast("Không thể tải số liệu giám sát hệ thống", "error");
    }
  } finally {
    state.system.isLoading = false;
  }
}

function updateSystemDashboard(data) {
  const sys = data.system || {};
  const cpu = data.cpu || {};
  const mem = data.memory || {};
  const net = data.network || {};

  // 1. Host & Uptime
  if (elements.sysHostText) {
    elements.sysHostText.textContent = `${sys.hostname || "Linux"} (${sys.os || "Linux"})`;
  }
  if (elements.sysUptimeText) {
    elements.sysUptimeText.textContent = `Uptime: ${sys.uptime_formatted || "--"}`;
  }

  // 2. CPU Card (Đơn giản, gọn gàng, đủ ý)
  const cpuPct = Math.min(100, Math.max(0, cpu.percent || 0));
  if (elements.sysCpuVal) elements.sysCpuVal.textContent = `${cpuPct.toFixed(1)}%`;
  if (elements.sysCpuBar) {
    elements.sysCpuBar.style.width = `${cpuPct}%`;
    elements.sysCpuBar.classList.toggle("warn", cpuPct >= 70 && cpuPct < 85);
    elements.sysCpuBar.classList.toggle("danger", cpuPct >= 85);
  }
  if (elements.sysCpuTrend && sys.load_avg) {
    elements.sysCpuTrend.textContent = `Tải 1m: ${sys.load_avg[0]}`;
  }
  if (elements.sysCpuCoresBadge) {
    elements.sysCpuCoresBadge.textContent = `${cpu.cores_count || 1} nhân`;
  }
  if (elements.sysCpuModelBrief) {
    const rawModel = cpu.model || "CPU";
    // Rút gọn bớt đuôi dài "with Radeon Graphics" để gọn gàng
    const cleanModel = rawModel.split(" with ")[0].trim();
    elements.sysCpuModelBrief.textContent = cleanModel;
    elements.sysCpuModelBrief.title = cpu.model || "";
  }
  if (elements.sysCpuCoresBrief && cpu.cores && cpu.cores.length > 0) {
    elements.sysCpuCoresBrief.textContent = cpu.cores.map(c => `${c.core.replace("cpu", "c")}: ${Math.round(c.percent)}%`).join(" • ");
  }

  // 3. RAM Card (Đơn giản, chỉ hiển thị GB dễ đọc, bỏ MB lặp lại)
  const ramPct = Math.min(100, Math.max(0, mem.percent || 0));
  if (elements.sysRamVal) elements.sysRamVal.textContent = `${ramPct.toFixed(1)}%`;
  if (elements.sysRamBar) {
    elements.sysRamBar.style.width = `${ramPct}%`;
    elements.sysRamBar.classList.toggle("warn", ramPct >= 75 && ramPct < 90);
    elements.sysRamBar.classList.toggle("danger", ramPct >= 90);
  }
  if (elements.sysRamTotalBadge) {
    elements.sysRamTotalBadge.textContent = mem.total_formatted || `${mem.total_mb} MB`;
  }
  if (elements.sysRamRatio) {
    elements.sysRamRatio.textContent = `${mem.used_formatted} / ${mem.total_formatted}`;
  }
  if (elements.sysRamDetailText) {
    elements.sysRamDetailText.textContent = `Khả dụng: ${mem.available_formatted}`;
  }
  if (elements.sysSwapBrief) {
    elements.sysSwapBrief.textContent = `Swap: ${mem.swap_used_mb} MB (${Math.round(mem.swap_percent)}%)`;
  }

  // 4. Network Cards (Lọc theo card được chọn hoặc tính tổng toàn hệ thống)
  const ifaces = net.interfaces || [];

  // Populate Card Selector if needed
  if (elements.sysIfaceSelect && elements.sysIfaceSelect.options.length <= 1 && ifaces.length > 0) {
    const curVal = elements.sysIfaceSelect.value || "all";
    const opts = ['<option value="all">Tất cả card mạng (Tổng hợp)</option>'];
    ifaces.forEach(iface => {
      if (!iface.is_loopback) {
        const ipLabel = iface.ip ? ` (${iface.ip})` : "";
        opts.push(`<option value="${escapeHtml(iface.name)}">${escapeHtml(iface.name)}${ipLabel}</option>`);
      }
    });
    elements.sysIfaceSelect.innerHTML = opts.join("");
    elements.sysIfaceSelect.value = curVal;
  }

  const selIface = state.system.selectedInterface || "all";
  let rxRate = 0;
  let txRate = 0;
  let rxFormatted = "0 B/s";
  let txFormatted = "0 B/s";
  let rxTotalFormatted = "0 B";
  let txTotalFormatted = "0 B";
  let rxPktsSec = 0;
  let txPktsSec = 0;
  let ifaceBadgeText = "Tất cả (All)";

  if (selIface === "all") {
    rxRate = net.rx_bytes_sec || 0;
    txRate = net.tx_bytes_sec || 0;
    rxFormatted = net.rx_rate_formatted || "0 B/s";
    txFormatted = net.tx_rate_formatted || "0 B/s";
    rxTotalFormatted = net.total_rx_formatted || "0 B";
    txTotalFormatted = net.total_tx_formatted || "0 B";
    rxPktsSec = net.rx_pkts_sec || 0;
    txPktsSec = net.tx_pkts_sec || 0;
    ifaceBadgeText = "Tất cả (All)";
  } else {
    const found = ifaces.find(i => i.name === selIface);
    if (found) {
      rxRate = found.rx_bytes_sec || 0;
      txRate = found.tx_bytes_sec || 0;
      rxFormatted = found.rx_rate_formatted || "0 B/s";
      txFormatted = found.tx_rate_formatted || "0 B/s";
      rxTotalFormatted = found.rx_total_formatted || "0 B";
      txTotalFormatted = found.tx_total_formatted || "0 B";
      rxPktsSec = found.rx_pkts_sec || 0;
      txPktsSec = found.tx_pkts_sec || 0;
      ifaceBadgeText = found.name;
    }
  }

  if (elements.sysRxRateVal) elements.sysRxRateVal.textContent = rxFormatted;
  if (elements.sysRxPktsBrief) elements.sysRxPktsBrief.textContent = `${rxPktsSec} gói/s`;
  if (elements.sysRxTotalVal) elements.sysRxTotalVal.textContent = rxTotalFormatted;
  if (elements.sysRxBar) {
    const rxActivity = Math.min(100, Math.max(6, (rxRate / (1024 * 1024)) * 100));
    elements.sysRxBar.style.width = `${rxActivity}%`;
  }

  if (elements.sysTxRateVal) elements.sysTxRateVal.textContent = txFormatted;
  if (elements.sysTxPktsBrief) elements.sysTxPktsBrief.textContent = `${txPktsSec} gói/s`;
  if (elements.sysTxTotalVal) elements.sysTxTotalVal.textContent = txTotalFormatted;
  if (elements.sysTxBar) {
    const txActivity = Math.min(100, Math.max(6, (txRate / (1024 * 1024)) * 100));
    elements.sysTxBar.style.width = `${txActivity}%`;
  }

  if (elements.sysPrimaryIfaceRx) elements.sysPrimaryIfaceRx.textContent = ifaceBadgeText;
  if (elements.sysPrimaryIfaceTx) elements.sysPrimaryIfaceTx.textContent = ifaceBadgeText;

  // 5. Append to history for charts
  const hist = state.system.history;
  const now = new Date();
  const timeStr = now.toTimeString().split(" ")[0];

  hist.labels.push(timeStr);
  hist.cpu.push(cpuPct);
  hist.ram.push(ramPct);
  hist.rx.push(rxRate);
  hist.tx.push(txRate);

  if (hist.labels.length > hist.maxPoints) {
    hist.labels.shift();
    hist.cpu.shift();
    hist.ram.shift();
    hist.rx.shift();
    hist.tx.shift();
  }

  // Update legends
  if (elements.chartLegendCpu) elements.chartLegendCpu.textContent = `${cpuPct.toFixed(1)}%`;
  if (elements.chartLegendRam) elements.chartLegendRam.textContent = `${ramPct.toFixed(1)}%`;
  if (elements.chartLegendRx) elements.chartLegendRx.textContent = rxFormatted;
  if (elements.chartLegendTx) elements.chartLegendTx.textContent = txFormatted;

  // 6. Draw Charts
  renderSystemCharts();

  // 7. Render interfaces table
  renderNetInterfacesTable(ifaces);
}

function renderNetInterfacesTable(interfaces) {
  if (!elements.netInterfacesTableBody) return;
  if (!interfaces || interfaces.length === 0) {
    elements.netInterfacesTableBody.innerHTML = `<tr><td colspan="8" class="text-center py-4">Không tìm thấy card mạng nào</td></tr>`;
    return;
  }
  if (elements.netIfaceCountBadge) {
    elements.netIfaceCountBadge.textContent = `${interfaces.length} Card mạng`;
  }

  elements.netInterfacesTableBody.innerHTML = interfaces.map(iface => {
    const isLo = iface.is_loopback;
    const nameClass = isLo ? "font-mono text-muted" : "font-mono font-bold";
    const rxRateColor = iface.rx_bytes_sec > 1024 ? "text-success font-bold" : "text-primary";
    const txRateColor = iface.tx_bytes_sec > 1024 ? "text-warning font-bold" : "text-primary";
    const errorsTotal = (iface.rx_errors || 0) + (iface.tx_errors || 0);
    const dropsTotal = (iface.rx_dropped || 0) + (iface.tx_dropped || 0);
    const errDropBadge = (errorsTotal > 0 || dropsTotal > 0)
      ? `<span class="badge badge-action-captcha" title="Lỗi: ${errorsTotal}, Rớt: ${dropsTotal}">⚠️ ${errorsTotal} err / ${dropsTotal} drop</span>`
      : `<span class="badge" style="background: rgba(16,185,129,0.1); color: #10b981; border: 1px solid rgba(16,185,129,0.25)">0 lỗi</span>`;

    return `
      <tr>
        <td>
          <div class="target-col">
            <span class="${nameClass}">${escapeHtml(iface.name)}</span>
            ${iface.ip ? `<span class="scope-pill font-mono" style="background: rgba(16,185,129,0.12); color: #10b981; font-weight: 600;">${escapeHtml(iface.ip)}</span>` : (isLo ? '<span class="scope-pill">lo</span>' : '<span class="scope-pill" style="background: rgba(56,189,248,0.15); color: #38bdf8;">eth</span>')}
          </div>
        </td>
        <td>
          <span class="action-badge ${iface.type.includes('Vật lý') ? 'type-badge-local' : 'type-badge-hub'}">
            ${escapeHtml(iface.type)}
          </span>
        </td>
        <td class="text-right font-mono ${rxRateColor}">${escapeHtml(iface.rx_rate_formatted)}</td>
        <td class="text-right font-mono ${txRateColor}">${escapeHtml(iface.tx_rate_formatted)}</td>
        <td class="text-right font-mono">${escapeHtml(iface.rx_total_formatted)}</td>
        <td class="text-right font-mono">${escapeHtml(iface.tx_total_formatted)}</td>
        <td class="text-center font-mono font-xs">
          <div><span class="text-success">↓</span> ${Number(iface.rx_packets).toLocaleString()}</div>
          <div><span class="text-warning">↑</span> ${Number(iface.tx_packets).toLocaleString()}</div>
        </td>
        <td class="text-center">${errDropBadge}</td>
      </tr>
    `;
  }).join("");
}

function renderSystemCharts() {
  if (state.activeTab !== "tabSystemView") return;
  drawCpuRamChart();
  drawNetworkChart();
}

function drawCpuRamChart() {
  const canvas = elements.cpuRamCanvas;
  if (!canvas) return;
  const rect = canvas.parentElement.getBoundingClientRect();
  if (rect.width <= 0) return;

  const dpr = window.devicePixelRatio || 1;
  const w = rect.width;
  const h = 220;

  if (canvas.width !== Math.floor(w * dpr) || canvas.height !== Math.floor(h * dpr)) {
    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
  }

  const ctx = canvas.getContext("2d");
  ctx.save();
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const padLeft = 45;
  const padRight = 15;
  const padTop = 15;
  const padBottom = 25;
  const plotW = w - padLeft - padRight;
  const plotH = h - padTop - padBottom;

  const isDark = document.documentElement.getAttribute("data-theme") !== "light";
  const gridColor = isDark ? "rgba(255, 255, 255, 0.08)" : "rgba(0, 0, 0, 0.08)";
  const textColor = isDark ? "#8b949e" : "#64748b";

  // Grid & Y-axis labels
  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  ctx.fillStyle = textColor;
  ctx.font = "10px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
  ctx.textAlign = "right";
  ctx.textBaseline = "middle";

  const yTicks = [0, 25, 50, 75, 100];
  for (const tick of yTicks) {
    const y = padTop + plotH - (tick / 100) * plotH;
    ctx.beginPath();
    ctx.moveTo(padLeft, y);
    ctx.lineTo(padLeft + plotW, y);
    ctx.stroke();

    ctx.fillText(`${tick}%`, padLeft - 8, y);
  }

  const hist = state.system.history;
  const maxPts = hist.maxPoints;
  const count = hist.labels.length;

  if (count < 2) {
    ctx.restore();
    return;
  }

  function getX(i) {
    return padLeft + (i / (maxPts - 1)) * plotW;
  }

  // Draw RAM Area & Line (Purple)
  drawSeries(ctx, hist.ram, 100, padLeft, padTop, plotW, plotH, maxPts, "#a855f7", "rgba(168, 85, 247, 0.22)", "rgba(168, 85, 247, 0.0)");

  // Draw CPU Area & Line (Cyan)
  drawSeries(ctx, hist.cpu, 100, padLeft, padTop, plotW, plotH, maxPts, "#38bdf8", "rgba(56, 189, 248, 0.25)", "rgba(56, 189, 248, 0.0)");

  // Time labels on bottom
  ctx.textAlign = "center";
  ctx.textBaseline = "top";
  ctx.fillStyle = textColor;
  if (count > 0) {
    ctx.fillText(hist.labels[0], getX(0), padTop + plotH + 8);
    if (count > 10) {
      const midIdx = Math.floor(count / 2);
      ctx.fillText(hist.labels[midIdx], getX(midIdx), padTop + plotH + 8);
    }
    const lastIdx = count - 1;
    ctx.fillText(hist.labels[lastIdx], getX(lastIdx), padTop + plotH + 8);
  }

  ctx.restore();
}

function drawNetworkChart() {
  const canvas = elements.networkCanvas;
  if (!canvas) return;
  const rect = canvas.parentElement.getBoundingClientRect();
  if (rect.width <= 0) return;

  const dpr = window.devicePixelRatio || 1;
  const w = rect.width;
  const h = 220;

  if (canvas.width !== Math.floor(w * dpr) || canvas.height !== Math.floor(h * dpr)) {
    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
  }

  const ctx = canvas.getContext("2d");
  ctx.save();
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const padLeft = 65;
  const padRight = 15;
  const padTop = 15;
  const padBottom = 25;
  const plotW = w - padLeft - padRight;
  const plotH = h - padTop - padBottom;

  const isDark = document.documentElement.getAttribute("data-theme") !== "light";
  const gridColor = isDark ? "rgba(255, 255, 255, 0.08)" : "rgba(0, 0, 0, 0.08)";
  const textColor = isDark ? "#8b949e" : "#64748b";

  const hist = state.system.history;
  const maxPts = hist.maxPoints;
  const count = hist.labels.length;

  let peakVal = 1024;
  for (let i = 0; i < count; i++) {
    if (hist.rx[i] > peakVal) peakVal = hist.rx[i];
    if (hist.tx[i] > peakVal) peakVal = hist.tx[i];
  }
  const niceMax = getNiceCeil(peakVal * 1.25);

  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  ctx.fillStyle = textColor;
  ctx.font = "10px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
  ctx.textAlign = "right";
  ctx.textBaseline = "middle";

  const stepCount = 4;
  for (let i = 0; i <= stepCount; i++) {
    const val = (niceMax / stepCount) * i;
    const y = padTop + plotH - (i / stepCount) * plotH;
    ctx.beginPath();
    ctx.moveTo(padLeft, y);
    ctx.lineTo(padLeft + plotW, y);
    ctx.stroke();

    ctx.fillText(formatRate(val), padLeft - 8, y);
  }

  if (count < 2) {
    ctx.restore();
    return;
  }

  function getX(i) {
    return padLeft + (i / (maxPts - 1)) * plotW;
  }

  // Draw TX (Upload) Area & Line (Amber)
  drawSeries(ctx, hist.tx, niceMax, padLeft, padTop, plotW, plotH, maxPts, "#f59e0b", "rgba(245, 158, 11, 0.22)", "rgba(245, 158, 11, 0.0)");

  // Draw RX (Download) Area & Line (Emerald)
  drawSeries(ctx, hist.rx, niceMax, padLeft, padTop, plotW, plotH, maxPts, "#10b981", "rgba(16, 185, 129, 0.25)", "rgba(16, 185, 129, 0.0)");

  // Time labels on bottom
  ctx.textAlign = "center";
  ctx.textBaseline = "top";
  ctx.fillStyle = textColor;
  if (count > 0) {
    ctx.fillText(hist.labels[0], getX(0), padTop + plotH + 8);
    if (count > 10) {
      const midIdx = Math.floor(count / 2);
      ctx.fillText(hist.labels[midIdx], getX(midIdx), padTop + plotH + 8);
    }
    const lastIdx = count - 1;
    ctx.fillText(hist.labels[lastIdx], getX(lastIdx), padTop + plotH + 8);
  }

  ctx.restore();
}

function drawSeries(ctx, data, maxVal, padLeft, padTop, plotW, plotH, maxPts, strokeColor, gradTop, gradBottom) {
  const count = data.length;
  if (count === 0) return;

  function getX(i) {
    return padLeft + (i / (maxPts - 1)) * plotW;
  }
  function getY(v) {
    const clamped = Math.max(0, Math.min(maxVal, v));
    return padTop + plotH - (clamped / maxVal) * plotH;
  }

  // Area fill
  const grad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
  grad.addColorStop(0, gradTop);
  grad.addColorStop(1, gradBottom);

  ctx.beginPath();
  ctx.moveTo(getX(0), padTop + plotH);
  for (let i = 0; i < count; i++) {
    ctx.lineTo(getX(i), getY(data[i]));
  }
  ctx.lineTo(getX(count - 1), padTop + plotH);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Stroke line
  ctx.beginPath();
  for (let i = 0; i < count; i++) {
    const x = getX(i);
    const y = getY(data[i]);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.strokeStyle = strokeColor;
  ctx.lineWidth = 2.2;
  ctx.lineJoin = "round";
  ctx.stroke();

  // Latest point glowing dot
  if (count > 0) {
    const lastX = getX(count - 1);
    const lastY = getY(data[count - 1]);

    ctx.beginPath();
    ctx.arc(lastX, lastY, 5, 0, Math.PI * 2);
    ctx.fillStyle = strokeColor;
    ctx.fill();

    ctx.beginPath();
    ctx.arc(lastX, lastY, 2.5, 0, Math.PI * 2);
    ctx.fillStyle = "#ffffff";
    ctx.fill();
  }
}

function getNiceCeil(val) {
  if (val <= 0) return 1024;
  const factor = Math.pow(10, Math.floor(Math.log10(val)));
  const normalized = val / factor;
  let ceil;
  if (normalized <= 1) ceil = 1;
  else if (normalized <= 2) ceil = 2;
  else if (normalized <= 5) ceil = 5;
  else ceil = 10;
  return ceil * factor;
}

function formatBytes(bytes) {
  if (!bytes || isNaN(bytes) || bytes === 0) return "0 B";
  if (bytes >= 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
  if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  if (bytes >= 1024) return (bytes / 1024).toFixed(2) + " KB";
  return Math.round(bytes) + " B";
}

function formatRate(bps) {
  if (!bps || isNaN(bps) || bps === 0) return "0 B/s";
  if (bps >= 1024 * 1024) return (bps / (1024 * 1024)).toFixed(2) + " MB/s";
  if (bps >= 1024) return (bps / 1024).toFixed(2) + " KB/s";
  return Math.round(bps) + " B/s";
}

function getSourceBadgeClass(src) {
  if (!src) return "source-crowdsec";
  const s = src.toLowerCase();
  if (s.includes("capi")) return "source-capi";
  if (s.includes("cscli")) return "source-cscli";
  return "source-crowdsec";
}

function getActionBadgeClass(act) {
  if (!act) return "action-ban";
  const a = act.toLowerCase();
  if (a.includes("captcha")) return "action-captcha";
  if (a.includes("throttle")) return "action-throttle";
  return "action-ban";
}

function renderCountry(code) {
  if (!code || code === "-") return "-";
  return code.toUpperCase();
}

function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  const icons = { success: "✅", error: "❌", info: "ℹ️" };
  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || "ℹ️"}</span>
    <span class="toast-message">${escapeHtml(message)}</span>
  `;
  elements.toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(20px)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

window.copyToClipboard = function (text) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    showToast(`Đã sao chép IP: ${text}`, "info");
  }).catch(() => {
    const input = document.createElement("input");
    input.value = text;
    document.body.appendChild(input);
    input.select();
    document.execCommand("copy");
    document.body.removeChild(input);
    showToast(`Đã sao chép IP: ${text}`, "info");
  });
};

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
