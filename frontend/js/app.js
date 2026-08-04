document.addEventListener('DOMContentLoaded', () => {
    /* ============================================================
       DOM REFERENCES
    ============================================================ */
    const navItems           = document.querySelectorAll('.nav-item');
    const tabContents        = document.querySelectorAll('.tab-content');
    const headerTitle        = document.getElementById('header-title');
    const headerSubtitle     = document.getElementById('header-subtitle');

    const operatorNameInput  = document.getElementById('operator-name');
    const targetUserInput    = document.getElementById('target-user');
    const accessDurationHid  = document.getElementById('access-duration');
    const sshKeyInput        = document.getElementById('ssh-key');
    const keyValidationMsg   = document.getElementById('key-validation-msg');
    const hostSelectorList   = document.getElementById('host-selector-list');
    const btnSelectAll       = document.getElementById('btn-select-all');

    const btnAddKey          = document.getElementById('btn-add-key');
    const btnRemoveKey       = document.getElementById('btn-remove-key');
    const btnPurgeUser       = document.getElementById('btn-purge-user');
    const btnDisableUser     = document.getElementById('btn-disable-user');
    const btnPingAll         = document.getElementById('btn-ping-all');

    const terminalOutput     = document.getElementById('terminal-output');
    const jobStatusBadge     = document.getElementById('job-status-badge');
    const currentJobId       = document.getElementById('current-job-id');
    const btnClearConsole    = document.getElementById('btn-clear-console');

    const matrixContainer    = document.getElementById('matrix-container');
    const matrixServerFilter = document.getElementById('matrix-server-filter');
    const btnRefreshMatrix   = document.getElementById('btn-refresh-matrix');

    const inventoryTableBody = document.getElementById('inventory-table-body');
    const inventoryCount     = document.getElementById('inventory-count');

    const auditUsername      = document.getElementById('audit-username');
    const btnRunAudit        = document.getElementById('btn-run-audit');
    const auditResultsContainer = document.getElementById('audit-results-container');

    const historyTableBody   = document.getElementById('history-table-body');
    const btnRefreshHistory  = document.getElementById('btn-refresh-history');

    const logModal           = document.getElementById('log-modal');
    const modalLogContent    = document.getElementById('modal-log-content');
    const btnCloseModal      = document.getElementById('btn-close-modal');

    // User Directory & Grant Access Modal
    const userDirectoryCards = document.getElementById('user-directory-cards');
    const userDirectorySearch = document.getElementById('user-directory-search');
    const btnRefreshUserDir   = document.getElementById('btn-refresh-user-dir');

    const grantAccessModal   = document.getElementById('grant-access-modal');
    const grantAccessForm    = document.getElementById('grant-access-form');
    const grantUserName      = document.getElementById('grant-user-name');
    const grantSourceHost    = document.getElementById('grant-source-host');
    const grantTargetHosts   = document.getElementById('grant-target-hosts');
    const grantOperatorName  = document.getElementById('grant-operator-name');
    const btnCloseGrantModal = document.getElementById('btn-close-grant-modal');
    const btnCancelGrant     = document.getElementById('btn-cancel-grant');

    // Key Inspector Modal
    const modalKeyInspector      = document.getElementById('modal-key-inspector');
    const inspectorUserTitle     = document.getElementById('inspector-user-title');
    const inspectorModalSubtitle = document.getElementById('inspector-modal-subtitle');
    const inspectorKeyCount      = document.getElementById('inspector-key-count');
    const inspectorKeyTableBody  = document.getElementById('inspector-key-table-body');
    const inspectorUserAddTarget   = document.getElementById('inspector-user-add-target');
    const inspectorAddKeyForm      = document.getElementById('inspector-add-key-form');
    const inspectorNewKey          = document.getElementById('inspector-new-key');
    const inspectorOperatorName    = document.getElementById('inspector-operator-name');
    const inspectorAddTargetHost   = document.getElementById('inspector-add-target-host');
    const inspectorKeyDetectedTag  = document.getElementById('inspector-key-detected-tag');
    const inspectorServerFilter    = document.getElementById('inspector-server-filter');
    const btnCloseInspector        = document.getElementById('btn-close-inspector');
    const btnRefreshInspector      = document.getElementById('btn-refresh-inspector');

    const inspectorAvatar          = document.getElementById('inspector-avatar');
    const inspectorUserDisplay     = document.getElementById('inspector-user-display');
    const inspectorUserStatusBadge = document.getElementById('inspector-user-status-badge');
    const inspectorHostDisplay     = document.getElementById('inspector-host-display');
    const btnInspectorGrant        = document.getElementById('btn-inspector-grant');
    const btnInspectorDisable      = document.getElementById('btn-inspector-disable');
    const btnInspectorEnable       = document.getElementById('btn-inspector-enable');
    const btnInspectorPurge        = document.getElementById('btn-inspector-purge');

    // Stats
    const statServers        = document.getElementById('stat-servers');
    const statUsers          = document.getElementById('stat-users');
    const statTemp           = document.getElementById('stat-temp');
    const statJobs           = document.getElementById('stat-jobs');

    /* ============================================================
       STATE
    ============================================================ */
    let inventoryData     = { groups: {}, all_hosts: [] };
    let serverUsersSummary = {};
    let fullMatrixData    = {};
    let pollTimer         = null;
    let activeJobId       = null;
    let activeInspectorUser = null;
    let activeInspectorHost = null;

    /* ============================================================
       DURATION TABS (Quick Preset Selector)
    ============================================================ */
    const durTabs          = document.querySelectorAll('.dur-tab');
    const customDaysInput  = document.getElementById('custom-days-input');
    const customDaysValue  = document.getElementById('custom-days-value');
    const expiryPreview    = document.getElementById('expiry-preview');
    const expiryPreviewTxt = document.getElementById('expiry-preview-text');

    function setDurationPreview(value) {
        if (value === 'permanent') {
            expiryPreview.className = 'duration-expiry-preview permanent show';
            expiryPreviewTxt.textContent = 'No expiration — permanent access granted';
        } else {
            const exp = calcExpiry(value);
            expiryPreview.className = 'duration-expiry-preview temp show';
            expiryPreviewTxt.textContent = exp ? `Access expires: ${exp.toLocaleString('en-IN', { dateStyle:'medium', timeStyle:'short' })}` : 'Invalid duration';
        }
    }

    function calcExpiry(value) {
        if (!value || value === 'permanent') return null;
        const now = new Date();
        if (value === '30m') { now.setMinutes(now.getMinutes() + 30); return now; }
        if (value === '1h')  { now.setHours(now.getHours() + 1); return now; }
        if (value === '12h') { now.setHours(now.getHours() + 12); return now; }
        const dayMatch = value.match(/^(\d+)d$/);
        if (dayMatch) { now.setDate(now.getDate() + parseInt(dayMatch[1])); return now; }
        return null;
    }

    durTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            durTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            const val = tab.getAttribute('data-value');

            if (val === 'custom') {
                customDaysInput.classList.add('visible');
                const days = parseInt(customDaysValue.value) || 30;
                accessDurationHid.value = `${days}d`;
            } else {
                customDaysInput.classList.remove('visible');
                accessDurationHid.value = val;
            }

            setDurationPreview(accessDurationHid.value);
        });
    });

    customDaysValue.addEventListener('input', () => {
        const days = parseInt(customDaysValue.value);
        if (days > 0) {
            accessDurationHid.value = `${days}d`;
            setDurationPreview(`${days}d`);
        }
    });

    setDurationPreview('permanent');

    /* ============================================================
       TAB NAVIGATION
    ============================================================ */
    const tabMeta = {
        'tab-global-search': { title: 'Global SSH Key Search', subtitle: 'Sub-50ms instant search across cached keys, fingerprints, comments, algorithms, and Linux user accounts.' },
        'tab-deploy':    { title: 'SSH Public Key Deployment', subtitle: 'Manage user SSH keys and temporary access across managed Linux servers.' },
        'tab-user-directory': { title: 'Discovered User Access Directory', subtitle: 'View all system users and delegate server access across your Linux infrastructure.' },
        'tab-matrix':    { title: 'Server Access Matrix', subtitle: 'Real-time server-by-server view of active SSH authorized keys.' },
        'tab-inventory': { title: 'Managed Infrastructure Inventory', subtitle: 'List of target managed servers, inventory groups, and connection status.' },
        'tab-auditor':   { title: 'Authorized Keys Auditor', subtitle: 'Scan and audit existing SSH keys directly from remote servers.' },
        'tab-sharing':   { title: 'Key Sharing Engine', subtitle: 'Securely share existing SSH public keys between managed servers and user accounts.' },
        'tab-sync-engine': { title: 'SSH Key Synchronization Engine', subtitle: 'Asynchronous background synchronization between managed Linux servers and local SQLite cache.' },
        'tab-history':   { title: 'Operator Audit Log & History', subtitle: 'Full accountability trail of who added, disabled, or revoked access.' }
    };

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const target = item.getAttribute('data-tab');
            navItems.forEach(n => n.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            item.classList.add('active');
            const targetContent = document.getElementById(target);
            if (targetContent) targetContent.classList.add('active');

            if (tabMeta[target]) {
                headerTitle.textContent    = tabMeta[target].title;
                headerSubtitle.textContent = tabMeta[target].subtitle;
            }

            if (target === 'tab-global-search') loadGlobalSearch();
            if (target === 'tab-user-directory') loadAccessMatrix(false);
            if (target === 'tab-matrix')    loadAccessMatrix(false);
            if (target === 'tab-inventory') loadAccessMatrix(false);
            if (target === 'tab-history')   loadJobHistory();
            if (target === 'tab-sharing')   initSharingModule();
            if (target === 'tab-sync-engine') loadSyncDashboard();
        });
    });

    /* ============================================================
       QUICK USER SELECT
    ============================================================ */
    window.selectUser = function(username) {
        targetUserInput.value = username;
    };

    /* ============================================================
       INVENTORY FETCH & HOST SELECTOR
    ============================================================ */
    function fetchInventory() {
        fetch('/api/inventory')
            .then(r => r.json())
            .then(data => {
                inventoryData = data;
                renderHostSelector();
                renderInventoryTable();
                populateMatrixFilter();
                populateGlobalSearchFilters();
                loadAccessMatrix(false);
                initSharingModule();
                loadGlobalSearch();
                loadSyncDashboard();
                loadStats();
            })
            .catch(err => {
                hostSelectorList.innerHTML = `<div class="error-msg"><i class="fa-solid fa-triangle-exclamation"></i> Failed to load inventory: ${err.message}</div>`;
            });
    }

    function populateMatrixFilter() {
        if (!matrixServerFilter) return;
        matrixServerFilter.innerHTML = '<option value="all">All Servers</option>';
        (inventoryData.all_hosts || []).forEach(host => {
            const opt = document.createElement('option');
            opt.value       = host.name;
            opt.textContent = `${host.name} (${host.ip})`;
            matrixServerFilter.appendChild(opt);
        });
    }

    function populateGlobalSearchFilters() {
        if (!globalFilterHost) return;
        globalFilterHost.innerHTML = '<option value="all">All Managed Servers</option>';
        if (syncSingleHostSelect) syncSingleHostSelect.innerHTML = '<option value="">-- Select Server Host --</option>';

        (inventoryData.all_hosts || []).forEach(host => {
            const opt = document.createElement('option');
            opt.value = host.name;
            opt.textContent = `${host.name} (${host.ip})`;
            globalFilterHost.appendChild(opt);

            if (syncSingleHostSelect) {
                const optS = document.createElement('option');
                optS.value = host.name;
                optS.textContent = `${host.name} (${host.ip})`;
                syncSingleHostSelect.appendChild(optS);
            }
        });

        if (globalFilterUser) {
            globalFilterUser.innerHTML = '<option value="all">All User Accounts</option>';
            const uDir = (fullMatrixData && fullMatrixData.user_directory) || {};
            Object.keys(uDir).sort().forEach(u => {
                const opt = document.createElement('option');
                opt.value = u;
                opt.textContent = u;
                globalFilterUser.appendChild(opt);
            });
        }
    }

    matrixServerFilter && matrixServerFilter.addEventListener('change', () => renderMatrixGrid(false, null));

    function renderHostSelector() {
        hostSelectorList.innerHTML = '';

        const allLabel = document.createElement('label');
        allLabel.className = 'host-item';
        allLabel.innerHTML = `
            <input type="checkbox" value="all" id="chk-all-hosts">
            <span><strong>All Managed Servers</strong></span>
            <span class="host-group-tag">Global</span>
        `;
        hostSelectorList.appendChild(allLabel);

        const chkAll = allLabel.querySelector('#chk-all-hosts');
        chkAll.addEventListener('change', () => {
            hostSelectorList.querySelectorAll('.chk-host').forEach(c => c.checked = chkAll.checked);
        });

        (inventoryData.all_hosts || []).forEach(host => {
            const item = document.createElement('label');
            item.className = 'host-item';
            item.innerHTML = `
                <input type="checkbox" value="${host.name}" class="chk-host">
                <span>${host.name} <code style="font-size:11px;">${host.ip}</code></span>
                <span class="host-group-tag">${host.group}</span>
            `;
            hostSelectorList.appendChild(item);
        });
    }

    btnSelectAll.addEventListener('click', () => {
        const boxes   = hostSelectorList.querySelectorAll('input[type="checkbox"]');
        const allChkd = Array.from(boxes).every(c => c.checked);
        boxes.forEach(c => c.checked = !allChkd);
        btnSelectAll.textContent = allChkd ? 'Select All' : 'Deselect All';
    });

    /* ============================================================
       SSH KEY VALIDATION
    ============================================================ */
    sshKeyInput.addEventListener('input', () => {
        const val      = sshKeyInput.value.trim();
        const prefixes = ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'sk-ssh-ed25519'];
        if (!val) {
            keyValidationMsg.className = 'key-status-indicator';
            keyValidationMsg.innerHTML = '<i class="fa-solid fa-circle-question"></i> Paste key below';
            return;
        }
        const valid = prefixes.some(p => val.startsWith(p));
        keyValidationMsg.className  = `key-status-indicator ${valid ? 'valid' : 'invalid'}`;
        keyValidationMsg.innerHTML  = valid
            ? '<i class="fa-solid fa-circle-check"></i> Valid SSH key'
            : '<i class="fa-solid fa-triangle-exclamation"></i> Unrecognized key format';
    });

    /* ============================================================
       KEY DEPLOYMENT ACTIONS
    ============================================================ */
    btnAddKey.addEventListener('click',     () => handleKeyDeploy('add'));
    btnRemoveKey.addEventListener('click',  () => handleKeyDeploy('remove'));
    btnDisableUser.addEventListener('click', () => {
        const u = targetUserInput.value.trim();
        if (!u) return alert('Enter the target username to disable access for.');
        if (confirm(`Temporarily DISABLE SSH access for user '${u}' on selected servers?\n\nThis removes their authorized_keys file (keeps the key on record). Re-add the key to restore access.`)) {
            handleKeyDeploy('disable');
        }
    });
    btnPurgeUser.addEventListener('click', () => {
        const u = targetUserInput.value.trim();
        if (!u) return alert('Enter the target username to purge.');
        if (confirm(`PURGE ALL SSH keys for user '${u}' on selected servers?\n\nThis permanently deletes their authorized_keys. Action cannot be undone.`)) {
            handleKeyDeploy('purge');
        }
    });

    function getSelectedHosts() {
        const chkAll  = document.getElementById('chk-all-hosts');
        if (chkAll && chkAll.checked) return ['all'];
        const checked = [...hostSelectorList.querySelectorAll('input.chk-host:checked')].map(c => c.value);
        return checked;
    }

    function handleKeyDeploy(action) {
        const operatorName   = operatorNameInput.value.trim() || 'Admin';
        const targetUser     = targetUserInput.value.trim();
        const sshKey         = sshKeyInput.value.trim();
        const comment        = document.getElementById('key-comment').value.trim();
        const duration       = accessDurationHid.value || 'permanent';
        const targetHosts    = getSelectedHosts();

        if (targetHosts.length === 0) {
            showTerminalError('Please select at least one target server before running the operation.');
            return alert('Please select at least one target server or "All Managed Servers".');
        }
        if (!targetUser) return alert('Please enter a target username.');
        if (action === 'add' && !sshKey) return alert('Please paste the SSH public key to add.');

        let finalAction = action;
        if (action === 'remove' && !sshKey) finalAction = 'purge';

        setTerminalStatus('DISPATCHING', 'warning');
        terminalOutput.textContent = `[${ts()}] Dispatching ${finalAction.toUpperCase()} for user '${targetUser}' on [${targetHosts.join(', ')}]\n[${ts()}] Operator: ${operatorName} | Duration: ${duration}\n`;

        fetch('/api/keys/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_hosts: targetHosts,
                target_user:  targetUser,
                ssh_key:      sshKey,
                action:       finalAction,
                comment:      comment,
                operator_name: operatorName,
                access_duration: duration
            })
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                setTerminalStatus('ERROR', 'danger');
                terminalOutput.textContent += `\n[${ts()}] Error: ${data.error}\n`;
                return;
            }
            activeJobId = data.job_id;
            currentJobId.innerHTML = `<i class="fa-solid fa-hashtag"></i> Job: ${activeJobId}`;
            setTerminalStatus('RUNNING', 'info');
            startLogPolling(activeJobId);
        })
        .catch(err => {
            setTerminalStatus('FAILED', 'danger');
            terminalOutput.textContent += `\n[${ts()}] Network error: ${err.message}\n`;
        });
    }

    function startLogPolling(jobId) {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(() => {
            fetch(`/api/jobs/${jobId}`)
                .then(r => r.json())
                .then(job => {
                    if (job.logs) {
                        terminalOutput.textContent = job.logs;
                        terminalOutput.scrollTop = terminalOutput.scrollHeight;
                    }
                    if (job.status === 'SUCCESS') {
                        setTerminalStatus('SUCCESS', 'success');
                        clearInterval(pollTimer);
                        loadAccessMatrix(false);
                        loadStats();
                    } else if (job.status === 'FAILED') {
                        setTerminalStatus('FAILED', 'danger');
                        clearInterval(pollTimer);
                    }
                })
                .catch(() => {});
        }, 1500);
    }

    function setTerminalStatus(text, type) {
        const classMap = { success:'badge-success', danger:'badge-danger', warning:'badge-warning', info:'badge-info', status:'badge-status' };
        jobStatusBadge.className = `badge ${classMap[type] || 'badge-status'}`;
        jobStatusBadge.textContent = text;
    }

    function showTerminalError(msg) {
        setTerminalStatus('ERROR', 'danger');
        terminalOutput.textContent = `[${ts()}] ${msg}\n`;
    }

    btnClearConsole.addEventListener('click', () => {
        terminalOutput.textContent = 'Console cleared. Ready for next operation.';
        setTerminalStatus('READY', 'status');
        currentJobId.innerHTML = '<i class="fa-solid fa-hashtag"></i> Job: --';
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    });

    btnPingAll.addEventListener('click', () => {
        btnPingAll.disabled = true;
        btnPingAll.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Pinging...';
        fetch('/api/ping', { method: 'POST' })
            .then(r => r.json())
            .then(data => {
                btnPingAll.disabled = false;
                btnPingAll.innerHTML = '<i class="fa-solid fa-network-wired"></i> Test Ansible Ping';
                alert(`Ansible Ping Result:\n\n${data.output}`);
            })
            .catch(err => {
                btnPingAll.disabled = false;
                btnPingAll.innerHTML = '<i class="fa-solid fa-network-wired"></i> Test Ansible Ping';
                alert(`Ping failed: ${err.message}`);
            });
    });

    /* ============================================================
       ACCESS MATRIX
    ============================================================ */
    btnRefreshMatrix.addEventListener('click', () => loadAccessMatrix(true));

    function loadAccessMatrix(forceRefresh = false) {
        if (forceRefresh) {
            btnRefreshMatrix.disabled = true;
            btnRefreshMatrix.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning...';
            matrixContainer.innerHTML  = '<div class="loading-spinner"><i class="fa-solid fa-circle-notch fa-spin"></i> Running live Ansible SSH key scan...</div>';
        }

        fetch(forceRefresh ? '/api/matrix?refresh=true' : '/api/matrix')
            .then(r => r.json())
            .then(data => {
                btnRefreshMatrix.disabled = false;
                btnRefreshMatrix.innerHTML = '<i class="fa-solid fa-rotate"></i> Live Scan Sync';
                fullMatrixData     = data;
                serverUsersSummary = data.server_users_summary || {};
                if (data.inventory && data.inventory.all_hosts) {
                    inventoryData = data.inventory;
                    populateMatrixFilter();
                    renderHostSelector();
                }
                renderInventoryTable();
                renderMatrixGrid(forceRefresh, data.error);
                renderUserDirectory(data.user_directory);
                loadStats();
            })
            .catch(err => {
                btnRefreshMatrix.disabled = false;
                btnRefreshMatrix.innerHTML = '<i class="fa-solid fa-rotate"></i> Live Scan Sync';
                if (forceRefresh) {
                    matrixContainer.innerHTML = `<div class="error-msg"><i class="fa-solid fa-triangle-exclamation"></i> Error: ${err.message}</div>`;
                }
            });
    }

    function renderMatrixGrid(wasLiveScan = false, scanError = null) {
        const matrix = fullMatrixData.matrix || {};
        const hosts  = (fullMatrixData.inventory && fullMatrixData.inventory.all_hosts)
            ? fullMatrixData.inventory.all_hosts
            : (inventoryData.all_hosts || []);
        const filter  = matrixServerFilter ? matrixServerFilter.value : 'all';
        const visible = filter === 'all' ? hosts : hosts.filter(h => h.name === filter);
        const totalEntries = Object.values(matrix).reduce((s, u) => s + Object.keys(u).length, 0);

        if (visible.length === 0) {
            matrixContainer.innerHTML = `
                <div class="empty-state-cta">
                    <i class="fa-solid fa-server" style="font-size:2.5rem;color:var(--accent-blue);margin-bottom:12px;"></i>
                    <h3>No servers found</h3>
                    <p>Check your <code>inventory.ini</code> file.</p>
                </div>`;
            return;
        }

        let html = '';

        // Error banner
        if (scanError) {
            html += `<div class="error-msg" style="margin-bottom:16px;"><i class="fa-solid fa-triangle-exclamation"></i> <strong>Scan error:</strong> ${scanError} — Showing last cached data.</div>`;
        }

        // Empty cache CTA
        if (totalEntries === 0 && !wasLiveScan) {
            html += `
                <div class="matrix-scan-cta">
                    <i class="fa-solid fa-satellite-dish" style="font-size:2.2rem;color:var(--accent-blue);"></i>
                    <h3>No cache data yet</h3>
                    <p>Run a Live Scan to discover active SSH key users across all managed servers.</p>
                    <button class="btn btn-primary" onclick="document.getElementById('btn-refresh-matrix').click()">
                        <i class="fa-solid fa-rotate"></i> Run Live Scan Now
                    </button>
                </div>`;
        }

        html += '<div class="matrix-grid">';

        visible.forEach(host => {
            const hostMatrix  = matrix[host.name] || {};
            const allUsers    = Object.keys(hostMatrix);
            const activeUsers = allUsers.filter(u => hostMatrix[u].has_access);

            html += `
                <div class="matrix-card">
                    <div class="matrix-card-header">
                        <div>
                            <h4><i class="fa-solid fa-server"></i> ${host.name}</h4>
                            <span class="fp-chip">${host.ip}</span>
                        </div>
                        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;">
                            <span class="badge ${activeUsers.length > 0 ? 'badge-success' : 'badge-status'}">
                                <span class="badge-dot"></span>
                                ${activeUsers.length} user${activeUsers.length !== 1 ? 's' : ''} with access
                            </span>
                            <span class="badge badge-primary">${host.group}</span>
                        </div>
                    </div>
                    <div class="user-access-list">`;

            if (allUsers.length === 0) {
                html += `
                    <div style="padding:24px;text-align:center;opacity:0.55;">
                        <i class="fa-solid fa-magnifying-glass" style="font-size:1.6rem;margin-bottom:8px;display:block;"></i>
                        <p style="margin:0;font-size:13px;">No data — click <strong>Live Scan Sync</strong> to scan.</p>
                    </div>`;
            } else {
                // Show only users WITH access
                activeUsers.forEach(user => {
                    const info = hostMatrix[user];
                    html += `
                        <div class="user-access-item active-access">
                            <div class="user-info">
                                <span class="user-name">
                                    <i class="fa-solid fa-user-check" style="color:var(--success);"></i>
                                    ${user}
                                </span>
                                <div class="user-meta">
                                    <span class="fp-chip key-count-badge-clickable" onclick="openKeyInspectorModal('${host.name}', '${user}')" title="Click to inspect all individual keys line-by-line">
                                        <i class="fa-solid fa-key" style="color:var(--primary);font-size:10px;"></i> ${info.keys_count} key${info.keys_count !== 1 ? 's' : ''}
                                    </span>
                                    <span class="badge badge-success" style="font-size:10px;">Active</span>
                                </div>
                            </div>
                            <div class="access-actions">
                                <button class="btn btn-outline btn-xs" title="Inspect individual keys line-by-line" onclick="openKeyInspectorModal('${host.name}', '${user}')">
                                    <i class="fa-solid fa-eye"></i> Inspect
                                </button>
                                <button class="btn btn-primary btn-xs" title="Grant this user access to another server" onclick="openGrantAccessModal('${user}')">
                                    <i class="fa-solid fa-key"></i> Grant
                                </button>
                                <button class="btn btn-secondary btn-xs" title="Disable access (keeps key on record, blocks SSH login)" onclick="disableUserOnHost('${user}', '${host.name}')">
                                    <i class="fa-solid fa-ban"></i> Disable
                                </button>
                                <button class="btn btn-danger btn-xs" title="Permanently revoke & delete SSH key" onclick="purgeUserOnHost('${user}', '${host.name}')">
                                    <i class="fa-solid fa-trash"></i> Revoke
                                </button>
                            </div>
                        </div>`;
                });

                // Disabled users (0 keys but in cache — previously had access)
                const disabledUsers = allUsers.filter(u => !hostMatrix[u].has_access);
                disabledUsers.forEach(user => {
                    html += `
                        <div class="user-access-item disabled-access">
                            <div class="user-info">
                                <span class="user-name">
                                    <i class="fa-solid fa-ban" style="color:var(--disabled);"></i>
                                    ${user}
                                </span>
                                <div class="user-meta">
                                    <span class="badge badge-disabled" style="font-size:10px;"><i class="fa-solid fa-ban"></i> Disabled</span>
                                    <span style="font-size:11px;color:var(--text-dim);">SSH login blocked</span>
                                </div>
                            </div>
                            <div class="access-actions">
                                <button class="btn btn-outline btn-xs" style="border-color:var(--success);color:var(--success);" title="Re-enable: paste key and re-add to restore access" onclick="reenableUserOnHost('${user}', '${host.name}')">
                                    <i class="fa-solid fa-rotate-left"></i> Re-enable
                                </button>
                            </div>
                        </div>`;
                });

                if (allUsers.length === 0 || (activeUsers.length === 0 && disabledUsers.length === 0)) {
                    html += `<p style="text-align:center;padding:16px;opacity:0.5;font-size:13px;">No active SSH keys on this server.</p>`;
                }
            }

            html += `</div></div>`;
        });

        html += '</div>';
        matrixContainer.innerHTML = html;
    }

    /* Quick Actions from Matrix — stay on matrix tab, update local cache instantly */
    window.disableUserOnHost = function(user, host) {
        if (!confirm(`Temporarily DISABLE SSH access for '${user}' on '${host}'?\n\nThis removes their authorized_keys file. The key is kept on record — click Re-enable to restore access.`)) return;

        // Optimistically update local matrix data immediately (instant UI feedback)
        if (fullMatrixData.matrix && fullMatrixData.matrix[host] && fullMatrixData.matrix[host][user]) {
            fullMatrixData.matrix[host][user].has_access = false;
            fullMatrixData.matrix[host][user].keys_count = 0;
            if (fullMatrixData.server_users_summary && fullMatrixData.server_users_summary[host]) {
                fullMatrixData.server_users_summary[host] = fullMatrixData.server_users_summary[host].filter(u => u !== user);
            }
            renderMatrixGrid(false, null); // Re-render instantly
        }

        // Fire Ansible in background
        const operatorName = operatorNameInput.value.trim() || 'Admin';
        fetch('/api/keys/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_hosts: [host],
                target_user:  user,
                ssh_key:      '',
                action:       'disable',
                comment:      'Disabled via Access Matrix',
                operator_name: operatorName,
                access_duration: 'permanent'
            })
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                alert(`Disable failed: ${data.error}`);
                loadAccessMatrix(false); // Revert on error
            }
            // Let background Ansible run — matrix is already updated optimistically
        })
        .catch(err => alert(`Error: ${err.message}`));
    };

    window.purgeUserOnHost = function(user, host) {
        if (!confirm(`REVOKE & permanently delete all SSH keys for '${user}' on '${host}'?\n\nThis cannot be undone.`)) return;

        // Optimistically remove from matrix
        if (fullMatrixData.matrix && fullMatrixData.matrix[host]) {
            delete fullMatrixData.matrix[host][user];
            if (fullMatrixData.server_users_summary && fullMatrixData.server_users_summary[host]) {
                fullMatrixData.server_users_summary[host] = fullMatrixData.server_users_summary[host].filter(u => u !== user);
            }
            renderMatrixGrid(false, null);
        }

        const operatorName = operatorNameInput.value.trim() || 'Admin';
        fetch('/api/keys/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_hosts: [host],
                target_user:  user,
                ssh_key:      '',
                action:       'purge',
                comment:      'Revoked via Access Matrix',
                operator_name: operatorName,
                access_duration: 'permanent'
            })
        })
        .then(r => r.json())
        .then(data => { if (data.error) { alert(`Revoke failed: ${data.error}`); loadAccessMatrix(false); } })
        .catch(err => alert(`Error: ${err.message}`));
    };

    window.reenableUserOnHost = function(user, host) {
        if (!confirm(`Re-enable SSH access for '${user}' on '${host}'?\n\nThis restores their original SSH key from backup. No key paste required.`)) return;

        // Optimistically restore in matrix immediately
        if (fullMatrixData.matrix && fullMatrixData.matrix[host]) {
            if (!fullMatrixData.matrix[host][user]) {
                fullMatrixData.matrix[host][user] = { has_access: true, keys_count: 1 };
            } else {
                fullMatrixData.matrix[host][user].has_access = true;
                fullMatrixData.matrix[host][user].keys_count = 1;
            }
            if (fullMatrixData.server_users_summary) {
                if (!fullMatrixData.server_users_summary[host]) fullMatrixData.server_users_summary[host] = [];
                if (!fullMatrixData.server_users_summary[host].includes(user)) {
                    fullMatrixData.server_users_summary[host].push(user);
                }
            }
            renderMatrixGrid(false, null);
        }

        const operatorName = operatorNameInput.value.trim() || 'Admin';
        fetch('/api/keys/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_hosts:    [host],
                target_user:     user,
                ssh_key:         '',
                action:          'enable',
                comment:         'Re-enabled via Access Matrix (restored from backup)',
                operator_name:   operatorName,
                access_duration: 'permanent'
            })
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                alert(`Re-enable failed: ${data.error}`);
                loadAccessMatrix(false); // Revert on error
            }
            // Ansible runs in background; matrix already shows enabled state
        })
        .catch(err => {
            alert(`Error: ${err.message}`);
            loadAccessMatrix(false);
        });
    };

    function setServerCheckboxes(targetHost) {
        hostSelectorList.querySelectorAll('input[type="checkbox"]').forEach(c => {
            c.checked = (c.value === targetHost);
        });
    }

    /* ============================================================
       INVENTORY TABLE & MANAGED SERVERS
    ============================================================ */
    /* ============================================================
       ENTERPRISE SERVER EXPLORER STATE & LOGIC
    ============================================================ */
    const explorerSearchInput   = document.getElementById('explorer-search-input');
    const explorerFilterEnv     = document.getElementById('explorer-filter-env');
    const explorerFilterRegion  = document.getElementById('explorer-filter-region');
    const explorerFilterStatus  = document.getElementById('explorer-filter-status');
    const btnToggleFavorites    = document.getElementById('btn-toggle-favorites');
    const btnResetExplorerFilters= document.getElementById('btn-reset-explorer-filters');
    const btnExplorerBatchPing  = document.getElementById('btn-explorer-batch-ping');
    const btnExplorerBulkSync   = document.getElementById('btn-explorer-bulk-sync');
    const chkExplorerSelectAll  = document.getElementById('chk-explorer-select-all');
    const explorerOnlineCount   = document.getElementById('explorer-online-count');

    let explorerFavoritesOnly   = false;
    let explorerDebounceTimer   = null;

    function renderInventoryTable() {
        loadServerExplorer();
    }

    function loadServerExplorer() {
        if (!inventoryTableBody) return;

        const q = explorerSearchInput ? explorerSearchInput.value.trim() : '';
        const env = explorerFilterEnv ? explorerFilterEnv.value : 'all';
        const region = explorerFilterRegion ? explorerFilterRegion.value : 'all';
        const status = explorerFilterStatus ? explorerFilterStatus.value : 'all';

        let url = `/api/servers/explorer?q=${encodeURIComponent(q)}&env=${encodeURIComponent(env)}&region=${encodeURIComponent(region)}&status=${encodeURIComponent(status)}&favorites=${explorerFavoritesOnly}`;

        fetch(url)
            .then(r => r.json())
            .then(data => {
                const servers = data.servers || [];
                if (inventoryCount) inventoryCount.textContent = `${data.total_servers || servers.length} Server${servers.length !== 1 ? 's' : ''}`;
                if (explorerOnlineCount) explorerOnlineCount.textContent = `${data.online_servers || 0} Online`;
                if (statServers) statServers.textContent = data.total_servers || servers.length;

                renderServerExplorerRows(servers);
            })
            .catch(err => {
                inventoryTableBody.innerHTML = `<tr><td colspan="8"><div class="error-msg">Error loading Server Explorer: ${err.message}</div></td></tr>`;
            });
    }

    function renderServerExplorerRows(servers) {
        if (servers.length === 0) {
            inventoryTableBody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center" style="padding:24px;color:var(--text-muted);">
                        <i class="fa-solid fa-server" style="font-size:2rem;margin-bottom:8px;display:block;opacity:0.4;"></i>
                        No managed servers found matching filter criteria.
                    </td>
                </tr>`;
            return;
        }

        const canManage = currentUser && currentUser.permissions && currentUser.permissions.includes('manage:servers');

        let html = '';
        servers.forEach(s => {
            const isFav = s.is_favorite;
            const isOnline = s.status === 'online';
            const envBadgeClass = s.environment === 'Production' ? 'badge-danger' : (s.environment === 'Staging' ? 'badge-warning' : 'badge-info');

            html += `
                <tr>
                    <td><input type="checkbox" class="chk-server-select" value="${escapeHtml(s.host)}"></td>
                    <td>
                        <div style="display:flex;align-items:center;gap:8px;">
                            <button class="btn-fav-star" onclick="toggleFavoriteServer('${escapeHtml(s.host)}', ${isFav ? 0 : 1})" style="background:none;border:none;cursor:pointer;font-size:14px;">
                                <i class="fa-solid fa-star" style="color:${isFav ? '#eab308' : 'rgba(255,255,255,0.2)'};"></i>
                            </button>
                            <strong>${escapeHtml(s.host)}</strong>
                        </div>
                    </td>
                    <td><code>${escapeHtml(s.ip || '172.0.16.84')}</code></td>
                    <td>
                        <span class="badge ${envBadgeClass}" style="font-size:10px;">${escapeHtml(s.environment || 'Production')}</span>
                        <span class="badge badge-status" style="font-size:10px;">${escapeHtml(s.region || 'us-east-1')}</span>
                    </td>
                    <td>
                        <span class="badge badge-primary" style="font-size:10px;">${escapeHtml(s.group_name || 'web_servers')}</span>
                        <div style="font-size:10.5px;color:var(--text-dim);margin-top:2px;">${escapeHtml(s.owner || 'DevOps')}</div>
                    </td>
                    <td>
                        <span class="badge ${isOnline ? 'badge-success' : 'badge-danger'}">
                            <span class="badge-dot"></span> ${isOnline ? 'ONLINE' : 'OFFLINE'}
                        </span>
                        <div style="font-size:10px;color:var(--text-dim);margin-top:2px;">Ping: ${escapeHtml(s.last_ping_at || 'Recently')}</div>
                    </td>
                    <td>
                        <span class="badge badge-success" style="cursor:pointer;" onclick="openKeyInspectorModal('${escapeHtml(s.host)}', 'root')">
                            <i class="fa-solid fa-user"></i> root
                        </span>
                    </td>
                    <td>
                        <div style="display:flex;gap:6px;">
                            <button class="btn btn-outline btn-xs" onclick="quickDeployToHost('${escapeHtml(s.host)}')">
                                <i class="fa-solid fa-key"></i> Target
                            </button>
                            ${canManage ? `
                                <button class="btn btn-outline btn-xs" style="color:var(--danger);border-color:rgba(239,68,68,0.3);" onclick="removeManagedServer('${escapeHtml(s.host)}')">
                                    <i class="fa-solid fa-trash"></i>
                                </button>
                            ` : ''}
                        </div>
                    </td>
                </tr>`;
        });

        inventoryTableBody.innerHTML = html;
    }

    window.toggleFavoriteServer = function(host, isFav) {
        fetch('/api/servers/metadata', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host: host, is_favorite: isFav })
        })
        .then(() => loadServerExplorer());
    };

    if (explorerSearchInput) {
        explorerSearchInput.addEventListener('input', () => {
            clearTimeout(explorerDebounceTimer);
            explorerDebounceTimer = setTimeout(loadServerExplorer, 150);
        });
    }

    if (explorerFilterEnv) explorerFilterEnv.addEventListener('change', loadServerExplorer);
    if (explorerFilterRegion) explorerFilterRegion.addEventListener('change', loadServerExplorer);
    if (explorerFilterStatus) explorerFilterStatus.addEventListener('change', loadServerExplorer);

    if (btnToggleFavorites) {
        btnToggleFavorites.addEventListener('click', () => {
            explorerFavoritesOnly = !explorerFavoritesOnly;
            btnToggleFavorites.style.background = explorerFavoritesOnly ? 'rgba(234,179,8,0.2)' : '';
            btnToggleFavorites.style.borderColor = explorerFavoritesOnly ? '#eab308' : '';
            loadServerExplorer();
        });
    }

    if (btnResetExplorerFilters) {
        btnResetExplorerFilters.addEventListener('click', () => {
            if (explorerSearchInput) explorerSearchInput.value = '';
            if (explorerFilterEnv) explorerFilterEnv.value = 'all';
            if (explorerFilterRegion) explorerFilterRegion.value = 'all';
            if (explorerFilterStatus) explorerFilterStatus.value = 'all';
            explorerFavoritesOnly = false;
            if (btnToggleFavorites) {
                btnToggleFavorites.style.background = '';
                btnToggleFavorites.style.borderColor = '';
            }
            loadServerExplorer();
        });
    }

    if (chkExplorerSelectAll) {
        chkExplorerSelectAll.addEventListener('change', () => {
            const checkboxes = document.querySelectorAll('.chk-server-select');
            checkboxes.forEach(c => c.checked = chkExplorerSelectAll.checked);
        });
    }

    if (btnExplorerBatchPing) {
        btnExplorerBatchPing.addEventListener('click', () => {
            const selected = Array.from(document.querySelectorAll('.chk-server-select:checked')).map(c => c.value);
            btnExplorerBatchPing.disabled = true;
            btnExplorerBatchPing.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Pinging...';

            fetch('/api/servers/ping_batch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hosts: selected })
            })
            .then(r => r.json())
            .then(data => {
                btnExplorerBatchPing.disabled = false;
                btnExplorerBatchPing.innerHTML = '<i class="fa-solid fa-network-wired"></i> Batch Ping';
                loadServerExplorer();
            })
            .catch(() => {
                btnExplorerBatchPing.disabled = false;
                btnExplorerBatchPing.innerHTML = '<i class="fa-solid fa-network-wired"></i> Batch Ping';
            });
        });
    }

    if (btnExplorerBulkSync) {
        btnExplorerBulkSync.addEventListener('click', () => {
            const selected = Array.from(document.querySelectorAll('.chk-server-select:checked')).map(c => c.value);
            if (selected.length === 0) {
                alert('Please select at least one server from the list to run Bulk Sync.');
                return;
            }
            triggerSyncJob('bulk', selected);
        });
    }

    window.quickTargetUserHost = function(user, host) {
        document.querySelector('[data-tab="tab-deploy"]').click();
        targetUserInput.value = user;
        setServerCheckboxes(host);
    };

    window.quickDeployToHost = function(host) {
        document.querySelector('[data-tab="tab-deploy"]').click();
        setServerCheckboxes(host);
    };

    // Modal Add Managed Server Handlers
    const btnOpenAddServerModal  = document.getElementById('btn-open-add-server-modal');
    const btnCloseAddServerModal = document.getElementById('btn-close-add-server-modal');
    const btnCancelAddServer     = document.getElementById('btn-cancel-add-server');
    const btnSubmitAddServer     = document.getElementById('btn-submit-add-server');
    const modalAddServer         = document.getElementById('modal-add-server');

    const tabBtnSingleServer     = document.getElementById('tab-btn-single-server');
    const tabBtnBulkServer       = document.getElementById('tab-btn-bulk-server');
    const formSingleServer       = document.getElementById('form-single-server');
    const formBulkServer         = document.getElementById('form-bulk-server');
    const addServerStatusMsg     = document.getElementById('add-server-status-msg');

    let currentAddServerMode     = 'single';

    if (btnOpenAddServerModal) {
        btnOpenAddServerModal.addEventListener('click', () => {
            if (modalAddServer) modalAddServer.style.display = 'flex';
            if (addServerStatusMsg) addServerStatusMsg.innerHTML = '';
        });
    }

    const closeAddServerModal = () => {
        if (modalAddServer) modalAddServer.style.display = 'none';
    };

    if (btnCloseAddServerModal) btnCloseAddServerModal.addEventListener('click', closeAddServerModal);
    if (btnCancelAddServer) btnCancelAddServer.addEventListener('click', closeAddServerModal);

    if (tabBtnSingleServer && tabBtnBulkServer) {
        tabBtnSingleServer.addEventListener('click', () => {
            currentAddServerMode = 'single';
            tabBtnSingleServer.className = 'btn btn-sm btn-primary';
            tabBtnBulkServer.className = 'btn btn-sm btn-outline';
            if (formSingleServer) formSingleServer.style.display = 'block';
            if (formBulkServer) formBulkServer.style.display = 'none';
        });
        tabBtnBulkServer.addEventListener('click', () => {
            currentAddServerMode = 'bulk';
            tabBtnBulkServer.className = 'btn btn-sm btn-primary';
            tabBtnSingleServer.className = 'btn btn-sm btn-outline';
            if (formSingleServer) formSingleServer.style.display = 'none';
            if (formBulkServer) formBulkServer.style.display = 'block';
        });
    }

    if (btnSubmitAddServer) {
        btnSubmitAddServer.addEventListener('click', () => {
            let payload = {};
            if (currentAddServerMode === 'single') {
                const sName = document.getElementById('add-server-name').value.trim();
                const sIp   = document.getElementById('add-server-ip').value.trim();
                const sGrp  = document.getElementById('add-server-group').value.trim() || 'web_servers';

                if (!sName || !sIp) {
                    if (addServerStatusMsg) addServerStatusMsg.innerHTML = '<span style="color:var(--danger);font-size:12px;">Please fill in both Server Host Alias and IP Address.</span>';
                    return;
                }
                payload = { servers: [{ name: sName, ip: sIp, group: sGrp }] };
            } else {
                const bulkGrp  = document.getElementById('add-bulk-group').value.trim() || 'web_servers';
                const bulkText = document.getElementById('add-bulk-text').value.trim();
                if (!bulkText) {
                    if (addServerStatusMsg) addServerStatusMsg.innerHTML = '<span style="color:var(--danger);font-size:12px;">Please paste at least one server line.</span>';
                    return;
                }
                payload = { group: bulkGrp, bulk_text: bulkText };
            }

            btnSubmitAddServer.disabled = true;
            btnSubmitAddServer.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';

            fetch('/api/servers/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(r => r.json())
            .then(data => {
                btnSubmitAddServer.disabled = false;
                btnSubmitAddServer.innerHTML = '<i class="fa-solid fa-plus-circle"></i> Save Server(s)';
                if (data.error) {
                    if (addServerStatusMsg) addServerStatusMsg.innerHTML = `<span style="color:var(--danger);font-size:12px;">${escapeHtml(data.error)}</span>`;
                } else {
                    if (addServerStatusMsg) addServerStatusMsg.innerHTML = `<span style="color:var(--success);font-size:12px;">${escapeHtml(data.message)}</span>`;
                    setTimeout(() => {
                        closeAddServerModal();
                        fetchInventory();
                    }, 1200);
                }
            })
            .catch(err => {
                btnSubmitAddServer.disabled = false;
                btnSubmitAddServer.innerHTML = '<i class="fa-solid fa-plus-circle"></i> Save Server(s)';
                if (addServerStatusMsg) addServerStatusMsg.innerHTML = `<span style="color:var(--danger);font-size:12px;">Failed to add server: ${err.message}</span>`;
            });
        });
    }

    window.removeManagedServer = function(hostName) {
        if (!confirm(`Are you sure you want to remove server '${hostName}' from Managed Inventory?`)) return;
        fetch('/api/servers/remove', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host: hostName })
        })
        .then(r => r.json())
        .then(data => {
            if (data.status === 'success') {
                fetchInventory();
            } else {
                alert(data.error || 'Failed to remove server');
            }
        })
        .catch(err => alert('Error removing server: ' + err.message));
    };

    /* ============================================================
       KEY AUDITOR
    ============================================================ */
    btnRunAudit.addEventListener('click', () => {
        const username = auditUsername.value.trim();
        if (!username) return alert('Enter username to audit.');
        auditResultsContainer.innerHTML = '<div class="loading-spinner"><i class="fa-solid fa-circle-notch fa-spin"></i> Querying remote servers via Ansible...</div>';

        fetch('/api/keys/audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_user: username, target_hosts: ['all'] })
        })
        .then(r => r.json())
        .then(data => {
            if (data.results && data.results.length > 0) {
                let html = `<div class="table-responsive"><table class="custom-table"><thead><tr>
                    <th>Server</th><th>User</th><th>Active Keys</th><th>Status</th>
                </tr></thead><tbody>`;
                data.results.forEach(r => {
                    html += `<tr>
                        <td><strong>${r.host}</strong></td>
                        <td><code>${r.user}</code></td>
                        <td><span class="badge ${r.keys_count > 0 ? 'badge-success' : 'badge-warning'}">${r.keys_count} key${r.keys_count !== 1 ? 's' : ''}</span></td>
                        <td><span class="badge badge-info">Scanned</span></td>
                    </tr>`;
                });
                html += '</tbody></table></div>';
                auditResultsContainer.innerHTML = html;
            } else {
                auditResultsContainer.innerHTML = `<pre class="terminal-output" style="max-height:250px;">${data.raw_output || 'No audit data returned.'}</pre>`;
            }
        })
        .catch(err => {
            auditResultsContainer.innerHTML = `<div class="error-msg">Audit failed: ${err.message}</div>`;
        });
    });

    /* ============================================================
       JOB HISTORY
    ============================================================ */
    btnRefreshHistory.addEventListener('click', loadJobHistory);

    function loadJobHistory() {
        historyTableBody.innerHTML = `<tr><td colspan="10" class="text-center" style="padding:20px;color:var(--text-muted);">Loading...</td></tr>`;
        fetch('/api/jobs')
            .then(r => r.json())
            .then(jobs => {
                historyTableBody.innerHTML = '';
                if (!jobs.length) {
                    historyTableBody.innerHTML = `<tr><td colspan="10" class="text-center" style="padding:24px;color:var(--text-muted);">No jobs recorded yet.</td></tr>`;
                    return;
                }
                jobs.forEach(j => {
                    const tr         = document.createElement('tr');
                    const statusMap  = { SUCCESS: 'badge-success', FAILED: 'badge-danger' };
                    const actionMap  = { ADD_KEY: 'badge-info', REVOKE_KEY: 'badge-danger', PURGE_USER_ACCESS: 'badge-warning', DISABLE_ACCESS: 'badge-disabled', EXPIRED_KEY_AUTO_REVOKED: 'badge-warning' };
                    const expiry     = j.expires_at && j.expires_at !== 'Permanent'
                        ? `<span class="badge badge-warning" style="font-size:10px;">${new Date(j.expires_at).toLocaleDateString()}</span>`
                        : `<span class="badge badge-status" style="font-size:10px;">Permanent</span>`;
                    tr.innerHTML = `
                        <td><code style="font-size:10px;">${j.id}</code></td>
                        <td style="white-space:nowrap;font-size:12px;">${new Date(j.timestamp).toLocaleString()}</td>
                        <td><strong><i class="fa-solid fa-user-tie"></i> ${j.operator_name || 'Admin'}</strong></td>
                        <td><span class="badge ${actionMap[j.action] || 'badge-status'}" style="font-size:10px;">${j.action}</span></td>
                        <td><code>${j.target_user}</code></td>
                        <td style="font-size:12px;">${j.target_hosts}</td>
                        <td>${expiry}</td>
                        <td><span class="badge ${statusMap[j.status] || 'badge-status'}">${j.status}</span></td>
                        <td style="font-size:12px;">${j.duration ? j.duration + 's' : '--'}</td>
                        <td>
                            <button class="btn btn-outline btn-xs" onclick="viewLogModal('${j.id}')">
                                <i class="fa-solid fa-terminal"></i> Log
                            </button>
                        </td>
                    `;
                    historyTableBody.appendChild(tr);
                });
                statJobs.textContent = jobs.length;
            })
            .catch(err => {
                historyTableBody.innerHTML = `<tr><td colspan="10"><div class="error-msg">Failed to load history: ${err.message}</div></td></tr>`;
            });
    }

    window.viewLogModal = function(jobId) {
        fetch(`/api/jobs/${jobId}`)
            .then(r => r.json())
            .then(job => {
                modalLogContent.textContent = job.logs || 'No log output recorded.';
                logModal.classList.add('active');
            });
    };

    btnCloseModal.addEventListener('click', () => logModal.classList.remove('active'));
    logModal.addEventListener('click', e => { if (e.target === logModal) logModal.classList.remove('active'); });

    /* ============================================================
       USER DIRECTORY & GRANT ACCESS LOGIC
    ============================================================ */
    if (btnRefreshUserDir) {
        btnRefreshUserDir.addEventListener('click', () => loadAccessMatrix(true));
    }
    if (userDirectorySearch) {
        userDirectorySearch.addEventListener('input', () => renderUserDirectory(fullMatrixData.user_directory));
    }

    function renderUserDirectory(userDirectory) {
        if (!userDirectoryCards) return;
        const uDir = userDirectory || (fullMatrixData && fullMatrixData.user_directory) || {};
        const hosts = (inventoryData && inventoryData.all_hosts) ? inventoryData.all_hosts : [];
        const searchTerm = (userDirectorySearch ? userDirectorySearch.value : '').toLowerCase().trim();

        const usernames = Object.keys(uDir).filter(u => u.toLowerCase().includes(searchTerm)).sort();

        if (usernames.length === 0) {
            userDirectoryCards.innerHTML = `
                <div class="empty-state" style="grid-column:1/-1;text-align:center;padding:40px;">
                    <i class="fa-solid fa-users-slash" style="font-size:2rem;color:var(--text-dim);margin-bottom:10px;display:block;"></i>
                    <p style="margin:0;">No users found ${searchTerm ? `matching "${searchTerm}"` : 'in cache'}. Run a Live Scan Sync to discover server users.</p>
                </div>`;
            return;
        }

        let html = '';

        usernames.forEach(user => {
            const uData = uDir[user];
            const servers = uData.servers || {};
            const activeCount = uData.active_hosts_count || 0;

            html += `
                <div class="user-dir-card">
                    <div class="user-dir-header">
                        <div class="user-avatar-badge">
                            <div class="user-avatar-icon">${user.charAt(0).toUpperCase()}</div>
                            <div class="user-title-info">
                                <h4>${user}</h4>
                                <span>${activeCount} of ${hosts.length} server${hosts.length !== 1 ? 's' : ''} active</span>
                            </div>
                        </div>
                        <span class="badge ${activeCount > 0 ? 'badge-success' : 'badge-status'}">
                            ${activeCount > 0 ? `${activeCount} Active` : 'No Active Access'}
                        </span>
                    </div>

                    <div class="server-access-list">`;

            hosts.forEach(h => {
                const sInfo = servers[h.name] || { status: 'none', keys_count: 0 };
                const st = sInfo.status || 'none';

                let badgeHtml = '';
                if (st === 'active') {
                    badgeHtml = `<span class="status-pill active"><i class="fa-solid fa-circle-check"></i> Active (${sInfo.keys_count} key${sInfo.keys_count !== 1 ? 's' : ''})</span>`;
                } else if (st === 'disabled') {
                    badgeHtml = `<span class="status-pill disabled"><i class="fa-solid fa-ban"></i> Disabled</span>`;
                } else {
                    badgeHtml = `<span class="status-pill none"><i class="fa-solid fa-circle"></i> No Access</span>`;
                }

                html += `
                    <div class="server-access-item">
                        <span class="server-pill"><i class="fa-solid fa-server" style="color:var(--primary);font-size:12px;"></i> ${h.name} (${h.ip})</span>
                        ${badgeHtml}
                    </div>`;
            });

            html += `
                    </div>

                    <div class="user-dir-actions">
                        <button class="btn btn-outline btn-xs" onclick="openKeyInspectorModal('', '${user}')" title="Inspect individual SSH keys line-by-line">
                            <i class="fa-solid fa-eye"></i> Inspect Keys
                        </button>
                        <button class="btn btn-primary btn-xs" onclick="openGrantAccessModal('${user}')" title="Grant access to another server using this user's SSH key">
                            <i class="fa-solid fa-key"></i> Grant Access
                        </button>
                        <button class="btn btn-secondary btn-xs" onclick="disableUserEverywhere('${user}')" title="Disable SSH access on all servers">
                            <i class="fa-solid fa-ban"></i> Disable All
                        </button>
                        <button class="btn btn-outline btn-xs" style="border-color:var(--success);color:var(--success);" onclick="enableUserEverywhere('${user}')" title="Re-enable SSH access on all servers">
                            <i class="fa-solid fa-rotate-left"></i> Re-enable All
                        </button>
                        <button class="btn btn-danger btn-xs" onclick="purgeUserEverywhere('${user}')" title="Permanently revoke access on all servers">
                            <i class="fa-solid fa-trash"></i> Revoke All
                        </button>
                    </div>
                </div>`;
        });

        userDirectoryCards.innerHTML = html;
    }

    window.openGrantAccessModal = function(user) {
        if (!grantAccessModal) return;
        grantUserName.value = user;
        const uDir = (fullMatrixData && fullMatrixData.user_directory) || {};
        const uData = uDir[user] || {};
        const servers = uData.servers || {};
        const hosts = (inventoryData && inventoryData.all_hosts) ? inventoryData.all_hosts : [];

        // Source host options: servers where user has keys or access
        grantSourceHost.innerHTML = '';
        const validSourceHosts = hosts.filter(h => {
            const st = (servers[h.name] && servers[h.name].status) || 'none';
            return st === 'active' || st === 'disabled';
        });

        if (validSourceHosts.length === 0) {
            hosts.forEach(h => {
                const opt = document.createElement('option');
                opt.value = h.name;
                opt.textContent = `${h.name} (${h.ip})`;
                grantSourceHost.appendChild(opt);
            });
        } else {
            validSourceHosts.forEach(h => {
                const opt = document.createElement('option');
                opt.value = h.name;
                opt.textContent = `${h.name} (${h.ip}) [${servers[h.name].status.toUpperCase()}]`;
                grantSourceHost.appendChild(opt);
            });
        }

        // Target hosts checkboxes: destination servers
        grantTargetHosts.innerHTML = '';
        hosts.forEach(h => {
            const label = document.createElement('label');
            label.className = 'checkbox-card';
            const isNoAccess = !servers[h.name] || servers[h.name].status === 'none';
            label.innerHTML = `
                <input type="checkbox" value="${h.name}" ${isNoAccess ? 'checked' : ''}>
                <span class="checkbox-box"><i class="fa-solid fa-check"></i></span>
                <div class="checkbox-info">
                    <span class="server-name">${h.name}</span>
                    <span class="server-ip">${h.ip}</span>
                </div>
            `;
            grantTargetHosts.appendChild(label);
        });

        grantAccessModal.classList.add('active');
    };

    if (btnCloseGrantModal) btnCloseGrantModal.addEventListener('click', () => grantAccessModal.classList.remove('active'));
    if (btnCancelGrant) btnCancelGrant.addEventListener('click', () => grantAccessModal.classList.remove('active'));
    if (grantAccessModal) grantAccessModal.addEventListener('click', e => { if (e.target === grantAccessModal) grantAccessModal.classList.remove('active'); });

    if (grantAccessForm) {
        grantAccessForm.addEventListener('submit', e => {
            e.preventDefault();
            const user = grantUserName.value;
            const sourceHost = grantSourceHost.value;
            const targetHosts = Array.from(grantTargetHosts.querySelectorAll('input:checked')).map(cb => cb.value);
            const operatorName = grantOperatorName.value.trim() || 'Admin';

            if (!targetHosts.length) {
                alert('Please select at least one target server to grant access.');
                return;
            }

            grantAccessModal.classList.remove('active');

            // Switch to Key Deployment tab to view terminal output console
            document.querySelector('[data-tab="tab-deploy"]').click();
            setTerminalStatus('STARTING...', 'info');
            terminalOutput.textContent = `[${ts()}] Dispatching Grant Access request for '${user}' from '${sourceHost}' to target servers: ${targetHosts.join(', ')}...\n`;

            fetch('/api/keys/grant_access', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target_user: user,
                    source_host: sourceHost,
                    target_hosts: targetHosts,
                    operator_name: operatorName
                })
            })
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    setTerminalStatus('ERROR', 'danger');
                    terminalOutput.textContent += `[${ts()}] Error: ${data.error}\n`;
                    return;
                }
                activeJobId = data.job_id;
                currentJobId.innerHTML = `<i class="fa-solid fa-hashtag"></i> Job: ${activeJobId}`;
                setTerminalStatus('RUNNING', 'info');
                startLogPolling(activeJobId);
            })
            .catch(err => {
                setTerminalStatus('FAILED', 'danger');
                terminalOutput.textContent += `[${ts()}] Network error: ${err.message}\n`;
            });
        });
    }

    window.disableUserEverywhere = function(user) {
        if (!confirm(`Disable SSH access for user '${user}' across ALL managed servers?`)) return;
        const hosts = (inventoryData && inventoryData.all_hosts) ? inventoryData.all_hosts.map(h => h.name) : ['all'];
        const operatorName = operatorNameInput ? operatorNameInput.value.trim() || 'Admin' : 'Admin';

        fetch('/api/keys/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_hosts: hosts,
                target_user: user,
                ssh_key: '',
                action: 'disable',
                comment: 'Disabled via User Directory',
                operator_name: operatorName
            })
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) alert(data.error);
            else {
                document.querySelector('[data-tab="tab-deploy"]').click();
                activeJobId = data.job_id;
                setTerminalStatus('RUNNING', 'info');
                startLogPolling(activeJobId);
            }
        });
    };

    window.enableUserEverywhere = function(user) {
        if (!confirm(`Re-enable SSH access for user '${user}' across ALL managed servers?`)) return;
        const hosts = (inventoryData && inventoryData.all_hosts) ? inventoryData.all_hosts.map(h => h.name) : ['all'];
        const operatorName = operatorNameInput ? operatorNameInput.value.trim() || 'Admin' : 'Admin';

        fetch('/api/keys/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_hosts: hosts,
                target_user: user,
                ssh_key: '',
                action: 'enable',
                comment: 'Re-enabled via User Directory',
                operator_name: operatorName
            })
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) alert(data.error);
            else {
                document.querySelector('[data-tab="tab-deploy"]').click();
                activeJobId = data.job_id;
                setTerminalStatus('RUNNING', 'info');
                startLogPolling(activeJobId);
            }
        });
    };

    window.purgeUserEverywhere = function(user) {
        if (!confirm(`PERMANENTLY REVOKE & PURGE access for user '${user}' across ALL managed servers?`)) return;
        const hosts = (inventoryData && inventoryData.all_hosts) ? inventoryData.all_hosts.map(h => h.name) : ['all'];
        const operatorName = operatorNameInput ? operatorNameInput.value.trim() || 'Admin' : 'Admin';

        fetch('/api/keys/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_hosts: hosts,
                target_user: user,
                ssh_key: '',
                action: 'purge',
                comment: 'Purged via User Directory',
                operator_name: operatorName
            })
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) alert(data.error);
            else {
                document.querySelector('[data-tab="tab-deploy"]').click();
                activeJobId = data.job_id;
                setTerminalStatus('RUNNING', 'info');
                startLogPolling(activeJobId);
            }
        });
    };

    /* ============================================================
       KEY INSPECTOR MODAL LOGIC
    ============================================================ */
    window.openKeyInspectorModal = function(host, user) {
        if (!modalKeyInspector) return;
        activeInspectorUser = user;
        activeInspectorHost = host || '';

        if (inspectorAvatar) inspectorAvatar.textContent = user.charAt(0).toUpperCase();
        if (inspectorUserDisplay) inspectorUserDisplay.textContent = user;
        if (inspectorUserTitle) inspectorUserTitle.textContent = `${user}`;
        if (inspectorHostDisplay) inspectorHostDisplay.textContent = host ? `Server Host: ${host}` : 'Server: All Managed Servers';
        if (inspectorUserAddTarget) inspectorUserAddTarget.textContent = `${user} ${host ? `@ ${host}` : ''}`;
        
        if (inspectorKeyCount) inspectorKeyCount.textContent = '...';
        if (inspectorKeyTableBody) inspectorKeyTableBody.innerHTML = `<tr><td colspan="6" class="text-center" style="padding:20px;color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin"></i> Loading authorized SSH keys for '${user}'...</td></tr>`;

        // Populate Add Target Host dropdown
        if (inspectorAddTargetHost) {
            inspectorAddTargetHost.innerHTML = '';
            const optAll = document.createElement('option');
            optAll.value = 'all';
            optAll.textContent = 'All Managed Servers';
            inspectorAddTargetHost.appendChild(optAll);

            const hosts = (inventoryData && inventoryData.all_hosts) ? inventoryData.all_hosts : [];
            hosts.forEach(h => {
                const opt = document.createElement('option');
                opt.value = h.name;
                opt.textContent = `${h.name} (${h.ip})`;
                inspectorAddTargetHost.appendChild(opt);
            });

            if (host && host !== 'all') inspectorAddTargetHost.value = host;
            else inspectorAddTargetHost.value = 'all';
        }

        if (inspectorNewKey) inspectorNewKey.value = '';
        if (inspectorKeyDetectedTag) inspectorKeyDetectedTag.innerHTML = '';

        modalKeyInspector.classList.add('active');

        loadInspectorKeys(host, user);
    };

    if (inspectorNewKey) {
        inspectorNewKey.addEventListener('input', () => {
            const str = inspectorNewKey.value.trim();
            const parts = str.split(/\s+/);
            if (parts.length >= 3) {
                const commentTag = parts.slice(2).join(' ');
                if (inspectorKeyDetectedTag) {
                    inspectorKeyDetectedTag.innerHTML = `<i class="fa-solid fa-circle-check" style="color:var(--success);"></i> Detected Key Tag: <code>${escapeHtml(commentTag)}</code>`;
                }
            } else {
                if (inspectorKeyDetectedTag) inspectorKeyDetectedTag.innerHTML = '';
            }
        });
    }

    // Inline Add Key form handler inside Inspector Modal
    if (inspectorAddKeyForm) {
        inspectorAddKeyForm.addEventListener('submit', e => {
            e.preventDefault();
            const newKey = inspectorNewKey.value.trim();
            const opName = inspectorOperatorName.value.trim() || 'Admin';
            const user = activeInspectorUser;

            const selectedHostVal = inspectorAddTargetHost ? inspectorAddTargetHost.value : (activeInspectorHost || 'all');
            const targetHosts = (selectedHostVal === 'all') 
                ? (inventoryData.all_hosts.map(h => h.name))
                : [selectedHostVal];

            if (!newKey) {
                alert('Please paste a valid SSH public key string.');
                return;
            }

            modalKeyInspector.classList.remove('active');

            document.querySelector('[data-tab="tab-deploy"]').click();
            setTerminalStatus('STARTING...', 'info');
            terminalOutput.textContent = `[${ts()}] Appending new SSH key to user '${user}' on ${targetHosts.join(', ')}...\n`;

            fetch('/api/keys/deploy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target_hosts: targetHosts,
                    target_user: user,
                    ssh_key: newKey,
                    action: 'add',
                    comment: `Appended via Key Inspector by ${opName}`,
                    operator_name: opName
                })
            })
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    setTerminalStatus('ERROR', 'danger');
                    terminalOutput.textContent += `[${ts()}] Error: ${data.error}\n`;
                    return;
                }
                inspectorNewKey.value = '';
                activeJobId = data.job_id;
                currentJobId.innerHTML = `<i class="fa-solid fa-hashtag"></i> Job: ${activeJobId}`;
                setTerminalStatus('RUNNING', 'info');
                startLogPolling(activeJobId);
            });
        });
    }

    let rawInspectData = [];

    function loadInspectorKeys(host, user) {
        fetch('/api/keys/inspect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host: host, user: user })
        })
        .then(r => r.json())
        .then(data => {
            rawInspectData = data.inspect_results || [];
            populateInspectorServerFilter(host);
            renderInspectorKeyTable();
        })
        .catch(err => {
            if (inspectorKeyTableBody) {
                inspectorKeyTableBody.innerHTML = `<tr><td colspan="6"><div class="error-msg">Failed to load keys: ${err.message}</div></td></tr>`;
            }
        });
    }

    function populateInspectorServerFilter(selectedHost) {
        if (!inspectorServerFilter) return;
        inspectorServerFilter.innerHTML = '';

        let totalKeys = 0;
        const optAll = document.createElement('option');
        optAll.value = 'all';

        rawInspectData.forEach(r => {
            const count = r.keys_list ? r.keys_list.length : (r.keys_count || 0);
            totalKeys += count;
            const opt = document.createElement('option');
            opt.value = r.host;
            opt.textContent = `${r.host} (${count} key${count !== 1 ? 's' : ''})`;
            inspectorServerFilter.appendChild(opt);
        });

        optAll.textContent = `All Servers (${totalKeys} keys)`;
        inspectorServerFilter.insertBefore(optAll, inspectorServerFilter.firstChild);

        if (selectedHost && selectedHost !== 'all' && rawInspectData.some(r => r.host === selectedHost)) {
            inspectorServerFilter.value = selectedHost;
        } else {
            inspectorServerFilter.value = 'all';
        }
    }

    function renderInspectorKeyTable() {
        const selectedHost = inspectorServerFilter ? inspectorServerFilter.value : 'all';
        let filteredResults = rawInspectData;
        if (selectedHost && selectedHost !== 'all') {
            filteredResults = rawInspectData.filter(r => r.host === selectedHost);
        }

        let allKeys = [];
        let isUserActive = false;

        filteredResults.forEach(r => {
            if (r.status === 'active') isUserActive = true;
            const kList = r.keys_list || [];
            kList.forEach(k => {
                allKeys.push({
                    host: r.host,
                    user: r.user,
                    algorithm: k.algorithm,
                    comment: k.comment,
                    fingerprint: k.fingerprint,
                    raw_key: k.raw_key
                });
            });
        });

        if (inspectorUserStatusBadge) {
            inspectorUserStatusBadge.className = `badge ${isUserActive ? 'badge-success' : 'badge-disabled'}`;
            inspectorUserStatusBadge.textContent = isUserActive ? 'Active' : 'Disabled / No Access';
        }

        const keyTableTitleLabel = document.getElementById('inspector-key-table-title-label');
        if (keyTableTitleLabel) {
            keyTableTitleLabel.textContent = (selectedHost && selectedHost !== 'all') 
                ? `Deployed Keys on ${selectedHost}` 
                : 'Deployed Keys (All Servers)';
        }

        if (inspectorKeyCount) inspectorKeyCount.textContent = allKeys.length;

        if (allKeys.length === 0) {
            inspectorKeyTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center" style="padding:24px;color:var(--text-muted);">
                        <i class="fa-solid fa-key" style="font-size:1.6rem;margin-bottom:8px;display:block;opacity:0.4;"></i>
                        No active SSH key lines found ${selectedHost !== 'all' ? `on <code>${selectedHost}</code>` : ''}.
                    </td>
                </tr>`;
            return;
        }

        let html = '';
        allKeys.forEach((k, idx) => {
            const rawKeyText = k.raw_key || '';
            const isMasked = rawKeyText.includes('[MASKED]');

            html += `
                <tr>
                    <td><strong>#${idx + 1}</strong></td>
                    <td><code>${escapeHtml(k.user)}</code></td>
                    <td><span class="badge badge-primary" style="font-size:10px;"><i class="fa-solid fa-server"></i> ${escapeHtml(k.host)}</span></td>
                    <td><span class="comment-chip"><i class="fa-solid fa-laptop-code"></i> ${escapeHtml(k.comment)}</span></td>
                    <td style="max-width:440px;">
                        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
                            <div>
                                <span class="badge badge-info" style="font-size:10px;">${escapeHtml(k.algorithm)}</span>
                                <code style="font-size:10px;color:var(--text-muted);">${escapeHtml(k.fingerprint)}</code>
                            </div>
                        </div>
                        <div style="background:rgba(15,23,42,0.85);border:1px solid rgba(255,255,255,0.1);padding:8px 10px;border-radius:6px;position:relative;margin-top:4px;">
                            <div style="font-size:10px;text-transform:uppercase;color:var(--text-dim);font-weight:700;margin-bottom:4px;display:flex;align-items:center;justify-content:space-between;">
                                <span><i class="fa-solid fa-key" style="color:var(--primary);"></i> Complete SSH Public Key String</span>
                            </div>
                            <div style="font-family:var(--font-mono);font-size:11px;color:var(--primary);word-break:break-all;padding-right:90px;line-height:1.4;max-height:100px;overflow-y:auto;user-select:all;">
                                ${escapeHtml(rawKeyText)}
                            </div>
                            ${!isMasked ? `
                                <button class="btn btn-primary btn-xs" onclick="copyTextToClipboard(\`${escapeJS(rawKeyText)}\`, this)" style="position:absolute;top:8px;right:8px;font-size:10.5px;padding:4px 8px;" title="Copy complete SSH public key to clipboard">
                                    <i class="fa-solid fa-copy"></i> Copy Key
                                </button>
                            ` : ''}
                        </div>
                    </td>
                    <td style="text-align:right;white-space:nowrap;vertical-align:top;">
                        <div style="display:flex;flex-direction:column;gap:6px;align-items:flex-end;">
                            <button class="btn btn-outline btn-xs" onclick="openCrossServerCopyModal('${k.user}', '${k.host}', \`${escapeJS(k.raw_key)}\`, \`${escapeJS(k.comment)}\`, \`${escapeJS(k.fingerprint)}\`)" title="Copy this key to another user or server account">
                                <i class="fa-solid fa-share font-xs"></i> Copy to User
                            </button>
                            <button class="btn btn-danger btn-xs" onclick="removeSingleKey('${k.user}', '${k.host}', \`${escapeJS(k.raw_key)}\`, \`${escapeJS(k.comment)}\`)" title="Remove ONLY this specific key line">
                                <i class="fa-solid fa-trash"></i> Remove Key
                            </button>
                        </div>
                    </td>
                </tr>`;
        });
        inspectorKeyTableBody.innerHTML = html;
    }

    if (inspectorServerFilter) {
        inspectorServerFilter.addEventListener('change', renderInspectorKeyTable);
    }

    if (btnRefreshInspector) {
        btnRefreshInspector.addEventListener('click', () => {
            if (activeInspectorUser) loadInspectorKeys(activeInspectorHost, activeInspectorUser);
        });
    }

    const closeAndRefreshInspector = () => {
        modalKeyInspector.classList.remove('active');
        loadAccessMatrix(false);
    };

    if (btnCloseInspector) btnCloseInspector.addEventListener('click', closeAndRefreshInspector);
    if (modalKeyInspector) modalKeyInspector.addEventListener('click', e => { if (e.target === modalKeyInspector) closeAndRefreshInspector(); });

    // Toolbar actions inside Inspector Modal
    if (btnInspectorGrant) {
        btnInspectorGrant.addEventListener('click', () => {
            if (modalKeyInspector) modalKeyInspector.classList.remove('active');
            if (activeInspectorUser) openGrantAccessModal(activeInspectorUser);
        });
    }
    if (btnInspectorDisable) {
        btnInspectorDisable.addEventListener('click', () => {
            if (!activeInspectorUser) return;
            if (activeInspectorHost) disableUserOnHost(activeInspectorUser, activeInspectorHost);
            else disableUserEverywhere(activeInspectorUser);
            if (modalKeyInspector) modalKeyInspector.classList.remove('active');
        });
    }
    if (btnInspectorEnable) {
        btnInspectorEnable.addEventListener('click', () => {
            if (!activeInspectorUser) return;
            if (activeInspectorHost) reenableUserOnHost(activeInspectorUser, activeInspectorHost);
            else enableUserEverywhere(activeInspectorUser);
            if (modalKeyInspector) modalKeyInspector.classList.remove('active');
        });
    }
    if (btnInspectorPurge) {
        btnInspectorPurge.addEventListener('click', () => {
            if (!activeInspectorUser) return;
            if (activeInspectorHost) purgeUserOnHost(activeInspectorUser, activeInspectorHost);
            else purgeUserEverywhere(activeInspectorUser);
            if (modalKeyInspector) modalKeyInspector.classList.remove('active');
        });
    }

    // Inline Add Key form handler inside Inspector Modal
    if (inspectorAddKeyForm) {
        inspectorAddKeyForm.addEventListener('submit', e => {
            e.preventDefault();
            const newKey = inspectorNewKey.value.trim();
            const opName = inspectorOperatorName.value.trim() || 'Admin';
            const user = activeInspectorUser;
            const targetHost = activeInspectorHost || (inventoryData.all_hosts.map(h => h.name));

            if (!newKey) {
                alert('Please paste a valid SSH public key string.');
                return;
            }

            modalKeyInspector.classList.remove('active');

            document.querySelector('[data-tab="tab-deploy"]').click();
            setTerminalStatus('STARTING...', 'info');
            terminalOutput.textContent = `[${ts()}] Appending new SSH key to user '${user}' on ${Array.isArray(targetHost) ? targetHost.join(',') : targetHost}...\n`;

            fetch('/api/keys/deploy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target_hosts: Array.isArray(targetHost) ? targetHost : [targetHost],
                    target_user: user,
                    ssh_key: newKey,
                    action: 'add',
                    comment: `Appended via Key Inspector by ${opName}`,
                    operator_name: opName
                })
            })
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    setTerminalStatus('ERROR', 'danger');
                    terminalOutput.textContent += `[${ts()}] Error: ${data.error}\n`;
                    return;
                }
                inspectorNewKey.value = '';
                activeJobId = data.job_id;
                currentJobId.innerHTML = `<i class="fa-solid fa-hashtag"></i> Job: ${activeJobId}`;
                setTerminalStatus('RUNNING', 'info');
                startLogPolling(activeJobId);
            });
        });
    }

    window.removeSingleKey = function(user, host, rawKey, comment) {
        if (!confirm(`Remove specific SSH key ('${comment}') for '${user}' on '${host}'?\n\nOther keys for this user will remain active.`)) return;

        const opName = inspectorOperatorName ? inspectorOperatorName.value.trim() || 'Admin' : 'Admin';

        if (modalKeyInspector) modalKeyInspector.classList.remove('active');

        document.querySelector('[data-tab="tab-deploy"]').click();
        setTerminalStatus('STARTING...', 'info');
        terminalOutput.textContent = `[${ts()}] Removing specific SSH key ('${comment}') for user '${user}' on host '${host}'...\n`;

        fetch('/api/keys/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_hosts: [host],
                target_user: user,
                ssh_key: rawKey,
                action: 'remove',
                comment: `Removed key '${comment}' via Key Inspector`,
                operator_name: opName
            })
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                setTerminalStatus('ERROR', 'danger');
                terminalOutput.textContent += `[${ts()}] Error: ${data.error}\n`;
                return;
            }
            activeJobId = data.job_id;
            currentJobId.innerHTML = `<i class="fa-solid fa-hashtag"></i> Job: ${activeJobId}`;
            setTerminalStatus('RUNNING', 'info');
            startLogPolling(activeJobId);
        });
    };

    /* ============================================================
       CROSS-SERVER KEY TRANSFER MODAL LOGIC
    ============================================================ */
    const modalCrossCopy          = document.getElementById('modal-cross-copy');
    const crossCopyForm           = document.getElementById('cross-copy-form');
    const crossCopySourceHost     = document.getElementById('cross-copy-source-host');
    const crossCopySourceUser     = document.getElementById('cross-copy-source-user');
    const crossCopyKeyComment     = document.getElementById('cross-copy-key-comment');
    const crossCopyKeyFp          = document.getElementById('cross-copy-key-fp');
    const crossCopyDestHost       = document.getElementById('cross-copy-dest-host');
    const crossCopyDestUserSelect = document.getElementById('cross-copy-dest-user-select');
    const crossCopyDestUserCustom = document.getElementById('cross-copy-dest-user-custom');
    const crossCopyOperatorName   = document.getElementById('cross-copy-operator-name');
    const btnCloseCrossCopy       = document.getElementById('btn-close-cross-copy');
    const btnCancelCrossCopy      = document.getElementById('btn-cancel-cross-copy');

    function loadDestinationUsersForHost(destHost, selectElem) {
        if (!selectElem) return;
        selectElem.innerHTML = '<option value="">Loading users for ' + (destHost || 'server') + '...</option>';

        fetch('/api/servers/users?host=' + encodeURIComponent(destHost || 'all'))
            .then(r => r.json())
            .then(data => {
                selectElem.innerHTML = '';
                const users = data.users || [];

                const optDefault = document.createElement('option');
                optDefault.value = '';
                optDefault.textContent = `-- Select Target User on ${data.host} (${users.length} available) --`;
                selectElem.appendChild(optDefault);

                users.forEach(u => {
                    const opt = document.createElement('option');
                    opt.value = u;
                    opt.textContent = `${u} (${data.host})`;
                    selectElem.appendChild(opt);
                });

                if (users.length === 0) {
                    const optEmpty = document.createElement('option');
                    optEmpty.value = '';
                    optEmpty.disabled = true;
                    optEmpty.textContent = 'No cached users found — run a Sync to refresh';
                    selectElem.appendChild(optEmpty);
                }
            })
            .catch(() => {
                selectElem.innerHTML = '<option value="">Error loading users</option>';
            });
    }

    if (crossCopyDestHost) {
        crossCopyDestHost.addEventListener('change', () => {
            loadDestinationUsersForHost(crossCopyDestHost.value, crossCopyDestUserSelect);
        });
    }

    const sharingDestHostElem = document.getElementById('sharing-dest-host');
    const sharingDestUserElem = document.getElementById('sharing-dest-user-select');
    if (sharingDestHostElem && sharingDestUserElem) {
        sharingDestHostElem.addEventListener('change', () => {
            loadDestinationUsersForHost(sharingDestHostElem.value, sharingDestUserElem);
        });
    }

    let activeCrossCopyKey = null;

    window.openCrossServerCopyModal = function(sourceUser, sourceHost, rawKey, comment, fingerprint) {
        if (!modalCrossCopy) return;

        activeCrossCopyKey = {
            source_user: sourceUser,
            source_host: sourceHost,
            raw_key: rawKey,
            comment: comment,
            fingerprint: fingerprint
        };

        if (crossCopySourceHost) crossCopySourceHost.textContent = sourceHost || 'All Servers';
        if (crossCopySourceUser) crossCopySourceUser.textContent = sourceUser;
        if (crossCopyKeyComment) crossCopyKeyComment.textContent = comment || 'SSH Public Key';
        if (crossCopyKeyFp) crossCopyKeyFp.textContent = fingerprint || (rawKey ? rawKey.substring(0, 50) + '...' : '');

        // Populate destination host select
        if (crossCopyDestHost) {
            crossCopyDestHost.innerHTML = '';
            const optAll = document.createElement('option');
            optAll.value = 'all';
            optAll.textContent = 'All Managed Servers';
            crossCopyDestHost.appendChild(optAll);

            const hosts = (inventoryData && inventoryData.all_hosts) ? inventoryData.all_hosts : [];
            hosts.forEach(h => {
                const opt = document.createElement('option');
                opt.value = h.name;
                opt.textContent = `${h.name} (${h.ip})`;
                crossCopyDestHost.appendChild(opt);
            });

            // Auto-select first target host if not all
            if (hosts.length > 0) {
                const targetInitial = (sourceHost && sourceHost !== 'all' && hosts.some(h => h.name !== sourceHost)) 
                    ? hosts.find(h => h.name !== sourceHost).name 
                    : hosts[0].name;
                crossCopyDestHost.value = targetInitial;
            }
        }

        // Dynamically load server-specific destination users
        const selectedHostVal = crossCopyDestHost ? crossCopyDestHost.value : 'all';
        loadDestinationUsersForHost(selectedHostVal, crossCopyDestUserSelect);
        if (crossCopyDestUserCustom) crossCopyDestUserCustom.value = '';

        modalCrossCopy.classList.add('active');
    };

    if (btnCloseCrossCopy) btnCloseCrossCopy.addEventListener('click', () => modalCrossCopy.classList.remove('active'));
    if (btnCancelCrossCopy) btnCancelCrossCopy.addEventListener('click', () => modalCrossCopy.classList.remove('active'));
    if (modalCrossCopy) modalCrossCopy.addEventListener('click', e => { if (e.target === modalCrossCopy) modalCrossCopy.classList.remove('active'); });

    // Handle Cross-Server Copy Form submit
    if (crossCopyForm) {
        crossCopyForm.addEventListener('submit', e => {
            e.preventDefault();
            if (!activeCrossCopyKey) return;

            const destHost = crossCopyDestHost ? crossCopyDestHost.value : 'all';
            const selUser = crossCopyDestUserSelect ? crossCopyDestUserSelect.value.trim() : '';
            const custUser = crossCopyDestUserCustom ? crossCopyDestUserCustom.value.trim() : '';
            const destUser = custUser || selUser;
            const opName = crossCopyOperatorName ? crossCopyOperatorName.value.trim() || 'Admin' : 'Admin';

            if (!destUser) {
                alert('Please select or type a destination target user account.');
                return;
            }

            modalCrossCopy.classList.remove('active');

            // Dispatch cross-server copy API request
            fetch('/api/keys/copy_cross_server', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    source_host: activeCrossCopyKey.source_host,
                    source_user: activeCrossCopyKey.source_user,
                    destination_host: destHost,
                    destination_user: destUser,
                    raw_key: activeCrossCopyKey.raw_key,
                    operator_name: opName
                })
            })
            .then(r => r.json())
            .then(data => {
                if (data.status === 'already_exists') {
                    alert(`ℹ️ Duplicate Prevention:\n\n${data.message}`);
                    return;
                }
                if (data.error) {
                    alert(`Error: ${data.error}`);
                    return;
                }

                if (modalKeyInspector) modalKeyInspector.classList.remove('active');

                // Switch to Key Deployment console
                document.querySelector('[data-tab="tab-deploy"]').click();
                activeJobId = data.job_id;
                currentJobId.innerHTML = `<i class="fa-solid fa-hashtag"></i> Job: ${activeJobId}`;
                setTerminalStatus('RUNNING', 'info');
                terminalOutput.textContent = `[${ts()}] ${data.message}\n`;
                startLogPolling(activeJobId);
            })
            .catch(err => {
                alert(`Network error during key copy: ${err.message}`);
            });
        });
    }

    /* ============================================================
       KEY SHARING ENGINE & MULTI-STEP WIZARD LOGIC
    ============================================================ */
    const sharingSourceHost     = document.getElementById('sharing-source-host');
    const sharingSourceUser     = document.getElementById('sharing-source-user');
    const sharingKeySearch      = document.getElementById('sharing-key-search');
    const sharingKeyCardsGrid   = document.getElementById('sharing-key-cards-grid');
    const sharingSelectedCount  = document.getElementById('sharing-selected-count');
    const btnSharingSelectAll   = document.getElementById('btn-sharing-select-all');
    const btnSharingClearAll    = document.getElementById('btn-sharing-clear-all');
    const btnSharingStep1Next   = document.getElementById('btn-sharing-step1-next');

    const sharingDestHost       = document.getElementById('sharing-dest-host');
    const sharingDestUserSelect = document.getElementById('sharing-dest-user-select');
    const sharingDestUserCustom = document.getElementById('sharing-dest-user-custom');
    const sharingDestSummaryTitle= document.getElementById('sharing-dest-summary-title');
    const sharingDestSummaryBody = document.getElementById('sharing-dest-summary-body');
    const btnSharingStep2Back   = document.getElementById('btn-sharing-step2-back');
    const btnSharingStep2Next   = document.getElementById('btn-sharing-step2-next');

    const sharingValidationContainer = document.getElementById('sharing-validation-results-container');
    const btnSharingStep3Back   = document.getElementById('btn-sharing-step3-back');
    const btnSharingStep3Next   = document.getElementById('btn-sharing-step3-next');

    const sharingReviewSource   = document.getElementById('sharing-review-source');
    const sharingReviewDest     = document.getElementById('sharing-review-dest');
    const sharingOperatorName   = document.getElementById('sharing-operator-name');
    const sharingReviewKeysList = document.getElementById('sharing-review-keys-list');
    const btnSharingStep4Back   = document.getElementById('btn-sharing-step4-back');
    const btnSharingStep4Execute= document.getElementById('btn-sharing-step4-execute');

    const sharingExecutionBanner= document.getElementById('sharing-execution-status-banner');
    const sharingExecutionLog   = document.getElementById('sharing-execution-log');
    const btnSharingStep5Reset  = document.getElementById('btn-sharing-step5-reset');

    let sharingState = {
        currentStep: 1,
        sourceHost: '',
        sourceUser: '',
        sourceKeys: [],
        selectedKeyIndices: new Set(),
        destHost: '',
        destUser: '',
        validationData: null
    };

    function initSharingModule() {
        if (!sharingSourceHost) return;

        // Populate Source & Dest Hosts
        sharingSourceHost.innerHTML = '';
        sharingDestHost.innerHTML = '';

        const optDefaultSource = document.createElement('option');
        optDefaultSource.value = '';
        optDefaultSource.textContent = '-- Select Source Server --';
        sharingSourceHost.appendChild(optDefaultSource);

        const optAllDest = document.createElement('option');
        optAllDest.value = 'all';
        optAllDest.textContent = 'All Managed Servers';
        sharingDestHost.appendChild(optAllDest);

        const hosts = (inventoryData && inventoryData.all_hosts) ? inventoryData.all_hosts : [];
        hosts.forEach(h => {
            const optS = document.createElement('option');
            optS.value = h.name;
            optS.textContent = `${h.name} (${h.ip})`;
            sharingSourceHost.appendChild(optS);

            const optD = document.createElement('option');
            optD.value = h.name;
            optD.textContent = `${h.name} (${h.ip})`;
            sharingDestHost.appendChild(optD);
        });

        // Populate Source & Dest User Selects from user directory
        sharingSourceUser.innerHTML = '';
        sharingDestUserSelect.innerHTML = '';

        const optDefaultUser = document.createElement('option');
        optDefaultUser.value = '';
        optDefaultUser.textContent = '-- Select User Account --';
        sharingSourceUser.appendChild(optDefaultUser);

        const optDefaultDestUser = document.createElement('option');
        optDefaultDestUser.value = '';
        optDefaultDestUser.textContent = '-- Select Destination User Account --';
        sharingDestUserSelect.appendChild(optDefaultDestUser);

        const uDir = (fullMatrixData && fullMatrixData.user_directory) || {};
        const knownUsers = Object.keys(uDir).sort();

        knownUsers.forEach(u => {
            const optS = document.createElement('option');
            optS.value = u;
            optS.textContent = u;
            sharingSourceUser.appendChild(optS);

            const optD = document.createElement('option');
            optD.value = u;
            optD.textContent = u;
            sharingDestUserSelect.appendChild(optD);
        });

        if (knownUsers.length > 0) {
            sharingSourceUser.value = knownUsers[0];
            if (hosts.length > 0) sharingSourceHost.value = hosts[0].name;
            loadSharingSourceKeys();
        }
    }

    function loadSharingSourceKeys() {
        const h = sharingSourceHost ? sharingSourceHost.value : '';
        const u = sharingSourceUser ? sharingSourceUser.value : '';

        sharingState.sourceHost = h;
        sharingState.sourceUser = u;
        sharingState.sourceKeys = [];
        sharingState.selectedKeyIndices.clear();

        if (!h || !u) {
            if (sharingKeyCardsGrid) sharingKeyCardsGrid.innerHTML = '<p class="empty-state">Select Source Server and User to view available SSH keys.</p>';
            updateSharingStep1NextButton();
            return;
        }

        if (sharingKeyCardsGrid) sharingKeyCardsGrid.innerHTML = '<p class="empty-state"><i class="fa-solid fa-circle-notch fa-spin"></i> Reading SSH authorized keys from source server...</p>';

        fetch('/api/keys/inspect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host: h, user: u, live: true })
        })
        .then(r => r.json())
        .then(data => {
            const inspectRes = data.inspect_results || [];
            let allK = [];
            inspectRes.forEach(r => {
                const kList = r.keys_list || [];
                kList.forEach(k => {
                    allK.push({
                        host: r.host,
                        user: r.user,
                        algorithm: k.algorithm || 'ssh-rsa',
                        comment: k.comment || 'SSH Key',
                        fingerprint: k.fingerprint || '',
                        raw_key: k.raw_key || ''
                    });
                });
            });

            sharingState.sourceKeys = allK;
            renderSharingKeyCards();
        })
        .catch(err => {
            if (sharingKeyCardsGrid) sharingKeyCardsGrid.innerHTML = `<div class="error-msg">Failed to load source keys: ${err.message}</div>`;
        });
    }

    function renderSharingKeyCards() {
        if (!sharingKeyCardsGrid) return;

        const query = sharingKeySearch ? sharingKeySearch.value.trim().toLowerCase() : '';
        const keys = sharingState.sourceKeys;

        if (!keys || keys.length === 0) {
            sharingKeyCardsGrid.innerHTML = '<p class="empty-state"><i class="fa-solid fa-key" style="font-size:1.6rem;margin-bottom:8px;display:block;opacity:0.4;"></i> No SSH public keys were found for this source user account.</p>';
            updateSharingStep1NextButton();
            return;
        }

        const filtered = keys.map((k, idx) => ({ k, idx })).filter(item => {
            if (!query) return true;
            const text = `${item.k.algorithm} ${item.k.comment} ${item.k.fingerprint} ${item.k.raw_key}`.toLowerCase();
            return text.includes(query);
        });

        if (filtered.length === 0) {
            sharingKeyCardsGrid.innerHTML = `<p class="empty-state">No keys matched search "${escapeHtml(query)}".</p>`;
            updateSharingStep1NextButton();
            return;
        }

        let html = '';
        filtered.forEach(item => {
            const k = item.k;
            const idx = item.idx;
            const isSelected = sharingState.selectedKeyIndices.has(idx);
            const algoClass = (k.algorithm || '').toLowerCase().includes('ed25519') ? 'ed25519' : ((k.algorithm || '').toLowerCase().includes('ecdsa') ? 'ecdsa' : 'rsa');

            html += `
                <div class="key-sharing-card ${isSelected ? 'selected' : ''}" onclick="toggleSharingKeySelection(${idx})">
                    <div class="key-sharing-card-header">
                        <span class="key-algo-badge ${algoClass}">${escapeHtml(k.algorithm)}</span>
                        <input type="checkbox" ${isSelected ? 'checked' : ''} onclick="event.stopPropagation(); toggleSharingKeySelection(${idx});" style="cursor:pointer;width:16px;height:16px;">
                    </div>
                    <div style="font-size:12px;font-weight:700;color:var(--text-main);margin-bottom:4px;word-break:break-all;">
                        <i class="fa-solid fa-laptop-code" style="color:var(--primary);margin-right:4px;"></i> ${escapeHtml(k.comment)}
                    </div>
                    <div style="font-family:var(--font-mono);font-size:10.5px;color:var(--text-muted);margin-bottom:6px;word-break:break-all;">
                        ${escapeHtml(k.fingerprint)}
                    </div>
                    <div style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim);background:rgba(0,0,0,0.2);padding:4px 6px;border-radius:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                        ${escapeHtml(k.raw_key)}
                    </div>
                </div>`;
        });

        sharingKeyCardsGrid.innerHTML = html;
        updateSharingStep1NextButton();
    }

    window.toggleSharingKeySelection = function(idx) {
        if (sharingState.selectedKeyIndices.has(idx)) {
            sharingState.selectedKeyIndices.delete(idx);
        } else {
            sharingState.selectedKeyIndices.add(idx);
        }
        renderSharingKeyCards();
    };

    function updateSharingStep1NextButton() {
        const count = sharingState.selectedKeyIndices.size;
        if (sharingSelectedCount) sharingSelectedCount.textContent = count;
        if (btnSharingStep1Next) {
            btnSharingStep1Next.disabled = (count === 0);
        }
    }

    if (sharingSourceHost) sharingSourceHost.addEventListener('change', loadSharingSourceKeys);
    if (sharingSourceUser) sharingSourceUser.addEventListener('change', loadSharingSourceKeys);
    if (sharingKeySearch) sharingKeySearch.addEventListener('input', renderSharingKeyCards);

    if (btnSharingSelectAll) {
        btnSharingSelectAll.addEventListener('click', () => {
            sharingState.sourceKeys.forEach((_, idx) => sharingState.selectedKeyIndices.add(idx));
            renderSharingKeyCards();
        });
    }

    if (btnSharingClearAll) {
        btnSharingClearAll.addEventListener('click', () => {
            sharingState.selectedKeyIndices.clear();
            renderSharingKeyCards();
        });
    }

    function gotoSharingStep(stepNum) {
        sharingState.currentStep = stepNum;

        for (let i = 1; i <= 5; i++) {
            const item = document.getElementById(`stepper-step-${i}`);
            const panel = document.getElementById(`sharing-panel-${i}`);

            if (item) {
                item.classList.remove('active', 'completed');
                if (i === stepNum) item.classList.add('active');
                else if (i < stepNum) item.classList.add('completed');
            }

            if (panel) {
                panel.style.display = (i === stepNum) ? 'block' : 'none';
            }
        }

        if (stepNum === 3) {
            runSharingValidation();
        }

        if (stepNum === 4) {
            renderSharingReview();
        }
    }

    if (btnSharingStep1Next) btnSharingStep1Next.addEventListener('click', () => gotoSharingStep(2));
    if (btnSharingStep2Back) btnSharingStep2Back.addEventListener('click', () => gotoSharingStep(1));
    if (btnSharingStep2Next) btnSharingStep2Next.addEventListener('click', () => gotoSharingStep(3));
    if (btnSharingStep3Back) btnSharingStep3Back.addEventListener('click', () => gotoSharingStep(2));
    if (btnSharingStep3Next) btnSharingStep3Next.addEventListener('click', () => gotoSharingStep(4));
    if (btnSharingStep4Back) btnSharingStep4Back.addEventListener('click', () => gotoSharingStep(3));

    function updateDestSummary() {
        const dHost = sharingDestHost ? sharingDestHost.value : 'all';
        const selU = sharingDestUserSelect ? sharingDestUserSelect.value.trim() : '';
        const custU = sharingDestUserCustom ? sharingDestUserCustom.value.trim() : '';
        const dUser = custU || selU;

        if (sharingDestSummaryTitle) sharingDestSummaryTitle.textContent = `Destination: ${dUser || 'None Selected'} @ ${dHost}`;
        if (sharingDestSummaryBody) {
            if (dUser) {
                sharingDestSummaryBody.textContent = `Target User: ${dUser} | Destination Server: ${dHost} | Ready to validate duplicate keys.`;
            } else {
                sharingDestSummaryBody.textContent = 'Select or type a destination target user account.';
            }
        }
    }

    if (sharingDestHost) sharingDestHost.addEventListener('change', updateDestSummary);
    if (sharingDestUserSelect) sharingDestUserSelect.addEventListener('change', updateDestSummary);
    if (sharingDestUserCustom) sharingDestUserCustom.addEventListener('input', updateDestSummary);

    function runSharingValidation() {
        const dHost = sharingDestHost ? sharingDestHost.value : 'all';
        const selU = sharingDestUserSelect ? sharingDestUserSelect.value.trim() : '';
        const custU = sharingDestUserCustom ? sharingDestUserCustom.value.trim() : '';
        const dUser = custU || selU;

        sharingState.destHost = dHost;
        sharingState.destUser = dUser;

        if (!dUser) {
            alert('Please select or enter a destination user account.');
            gotoSharingStep(2);
            return;
        }

        const selectedKeysObj = Array.from(sharingState.selectedKeyIndices).map(idx => sharingState.sourceKeys[idx]);

        if (sharingValidationContainer) {
            sharingValidationContainer.innerHTML = '<p class="empty-state"><i class="fa-solid fa-shield-halved fa-spin"></i> Validating selected keys against destination authorized_keys...</p>';
        }

        fetch('/api/keys/share_validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                destination_host: dHost,
                destination_user: dUser,
                keys: selectedKeysObj
            })
        })
        .then(r => r.json())
        .then(data => {
            sharingState.validationData = data;
            renderSharingValidationResults(data);
        })
        .catch(err => {
            if (sharingValidationContainer) {
                sharingValidationContainer.innerHTML = `<div class="error-msg">Validation error: ${err.message}</div>`;
            }
        });
    }

    function renderSharingValidationResults(data) {
        if (!sharingValidationContainer) return;

        const results = data.validation_results || [];
        if (results.length === 0) {
            sharingValidationContainer.innerHTML = '<p class="empty-state">No keys validated.</p>';
            return;
        }

        let html = `
            <div style="display:flex;gap:12px;margin-bottom:14px;flex-wrap:wrap;">
                <span class="badge badge-success" style="font-size:12px;padding:6px 12px;"><i class="fa-solid fa-circle-check"></i> ${data.eligible_count} Eligible New Key(s)</span>
                <span class="badge badge-warning" style="font-size:12px;padding:6px 12px;"><i class="fa-solid fa-triangle-exclamation"></i> ${data.duplicate_count} Already Exists (Skipped)</span>
            </div>`;

        results.forEach((res, i) => {
            const isDup = (res.status === 'already_exists');
            html += `
                <div class="validation-card ${res.status}">
                    <div>
                        <div style="display:flex;align-items:center;gap:8px;margin-bottom:2px;">
                            <strong style="font-size:13px;color:var(--text-main);">#${i + 1} ${escapeHtml(res.comment)}</strong>
                            <span class="key-algo-badge ${(res.algorithm || '').toLowerCase()}">${escapeHtml(res.algorithm)}</span>
                            ${isDup 
                                ? '<span class="badge badge-warning"><i class="fa-solid fa-ban"></i> Already Exists</span>' 
                                : '<span class="badge badge-success"><i class="fa-solid fa-plus-circle"></i> Ready to Share</span>'}
                        </div>
                        <code style="font-size:10.5px;color:var(--text-muted);">${escapeHtml(res.fingerprint)}</code>
                        <div style="font-size:11px;color:var(--text-dim);margin-top:2px;">${escapeHtml(res.status_message)}</div>
                    </div>
                </div>`;
        });

        sharingValidationContainer.innerHTML = html;

        if (btnSharingStep3Next) {
            btnSharingStep3Next.disabled = (data.eligible_count === 0);
        }
    }

    function renderSharingReview() {
        if (sharingReviewSource) sharingReviewSource.textContent = `${sharingState.sourceUser} @ ${sharingState.sourceHost}`;
        if (sharingReviewDest) sharingReviewDest.textContent = `${sharingState.destUser} @ ${sharingState.destHost}`;

        if (!sharingReviewKeysList) return;

        const valData = sharingState.validationData || {};
        const results = valData.validation_results || [];
        const eligibleResults = results.filter(r => r.status !== 'already_exists');

        if (eligibleResults.length === 0) {
            sharingReviewKeysList.innerHTML = '<p class="empty-state">All selected keys already exist on the destination. Nothing to share.</p>';
            if (btnSharingStep4Execute) btnSharingStep4Execute.disabled = true;
            return;
        }

        if (btnSharingStep4Execute) btnSharingStep4Execute.disabled = false;

        let html = `
            <div style="font-size:12px;font-weight:700;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px;">Keys to be Appended (${eligibleResults.length})</div>`;

        eligibleResults.forEach((res, i) => {
            html += `
                <div style="background:rgba(0,0,0,0.3);border:1px solid rgba(79,172,254,0.2);padding:10px 14px;border-radius:4px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;">
                    <div>
                        <strong style="font-size:12.5px;color:var(--accent-cyan);"><i class="fa-solid fa-key"></i> ${escapeHtml(res.comment)}</strong>
                        <div style="font-family:var(--font-mono);font-size:10.5px;color:var(--text-muted);">${escapeHtml(res.fingerprint)}</div>
                    </div>
                    <span class="badge badge-success"><i class="fa-solid fa-plus"></i> Appending</span>
                </div>`;
        });

        sharingReviewKeysList.innerHTML = html;
    }

    if (btnSharingStep4Execute) {
        btnSharingStep4Execute.addEventListener('click', () => {
            const valData = sharingState.validationData || {};
            const results = valData.validation_results || [];
            const eligibleKeys = results.filter(r => r.status !== 'already_exists').map(r => r.raw_key);
            const opName = sharingOperatorName ? sharingOperatorName.value.trim() || 'Admin' : 'Admin';

            if (eligibleKeys.length === 0) {
                alert('No eligible new keys to share.');
                return;
            }

            gotoSharingStep(5);

            if (sharingExecutionBanner) {
                sharingExecutionBanner.innerHTML = '<div class="alert alert-info"><i class="fa-solid fa-circle-notch fa-spin"></i> Initiating Key Sharing execution via Ansible...</div>';
            }
            if (sharingExecutionLog) sharingExecutionLog.textContent = `[${ts()}] Requesting key share for ${eligibleKeys.length} key(s) to ${sharingState.destUser}@${sharingState.destHost}...\n`;

            fetch('/api/keys/share_execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    source_host: sharingState.sourceHost,
                    source_user: sharingState.sourceUser,
                    destination_host: sharingState.destHost,
                    destination_user: sharingState.destUser,
                    eligible_keys: eligibleKeys,
                    operator_name: opName
                })
            })
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    if (sharingExecutionBanner) sharingExecutionBanner.innerHTML = `<div class="alert alert-danger"><i class="fa-solid fa-circle-xmark"></i> ${data.error}</div>`;
                    return;
                }

                activeJobId = data.job_id;
                startSharingLogPolling(activeJobId);
            })
            .catch(err => {
                if (sharingExecutionBanner) sharingExecutionBanner.innerHTML = `<div class="alert alert-danger"><i class="fa-solid fa-circle-xmark"></i> Network error: ${err.message}</div>`;
            });
        });
    }

    function startSharingLogPolling(jobId) {
        const interval = setInterval(() => {
            fetch(`/api/jobs/${jobId}/logs`)
                .then(r => r.json())
                .then(job => {
                    if (sharingExecutionLog) {
                        sharingExecutionLog.textContent = job.logs || 'Running playbook...';
                        sharingExecutionLog.scrollTop = sharingExecutionLog.scrollHeight;
                    }

                    if (job.status === 'SUCCESS') {
                        clearInterval(interval);
                        if (sharingExecutionBanner) {
                            sharingExecutionBanner.innerHTML = `<div class="alert alert-success"><i class="fa-solid fa-circle-check"></i> Key Sharing Completed Successfully! Key(s) appended to ${escapeHtml(sharingState.destUser)} on ${escapeHtml(sharingState.destHost)}.</div>`;
                        }
                    } else if (job.status === 'FAILED') {
                        clearInterval(interval);
                        if (sharingExecutionBanner) {
                            sharingExecutionBanner.innerHTML = `<div class="alert alert-danger"><i class="fa-solid fa-triangle-exclamation"></i> Key Sharing Execution Failed. Check logs above.</div>`;
                        }
                    }
                })
                .catch(() => {});
        }, 1500);
    }

    const headerLastSyncedTime = document.getElementById('header-last-synced-time');
    const btnHeaderSyncNow     = document.getElementById('btn-header-sync-now');

    function updateHeaderLastSynced(syncTime) {
        if (!headerLastSyncedTime) return;
        if (!syncTime || syncTime === 'Never') {
            headerLastSyncedTime.textContent = 'No sync performed yet';
            headerLastSyncedTime.style.color = 'var(--text-muted)';
        } else {
            headerLastSyncedTime.textContent = syncTime;
            headerLastSyncedTime.style.color = 'var(--primary)';
        }
    }

    if (btnHeaderSyncNow) {
        btnHeaderSyncNow.addEventListener('click', () => {
            btnHeaderSyncNow.disabled = true;
            btnHeaderSyncNow.innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin"></i> Syncing...';
            const tabBtn = document.querySelector('[data-tab="tab-sync-engine"]');
            if (tabBtn) tabBtn.click();
            triggerSyncJob('full', ['all']);
            setTimeout(() => {
                btnHeaderSyncNow.disabled = false;
                btnHeaderSyncNow.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Sync Now';
            }, 3000);
        });
    }

    if (btnSharingStep5Reset) {
        btnSharingStep5Reset.addEventListener('click', () => {
            gotoSharingStep(1);
            loadSharingSourceKeys();
        });
    }

    function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }

    function escapeJS(str) {
        if (!str) return '';
        return str.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$');
    }
    function loadStats() {
        // Count unique users with access
        const matrix = fullMatrixData.matrix || {};
        const allActiveUsers = new Set();
        Object.values(matrix).forEach(hostUsers => {
            Object.entries(hostUsers).forEach(([u, info]) => {
                if (info.has_access) allActiveUsers.add(u);
            });
        });
        statUsers.textContent = allActiveUsers.size || '--';

        // Temp keys
        fetch('/api/jobs')
            .then(r => r.json())
            .then(jobs => {
                const now       = new Date();
                const tempActive = jobs.filter(j => j.expires_at && j.expires_at !== 'Permanent' && new Date(j.expires_at) > now && j.status === 'SUCCESS').length;
                statTemp.textContent = tempActive;
                statJobs.textContent = jobs.length;
            })
            .catch(() => {});
    }

    /* ============================================================
       GLOBAL SEARCH & SYNC ENGINE CONTROLLERS
    ============================================================ */
    const globalSearchInput   = document.getElementById('global-search-input');
    const globalFilterHost    = document.getElementById('global-filter-host');
    const globalFilterUser    = document.getElementById('global-filter-user');
    const globalFilterAlgo    = document.getElementById('global-filter-algo');
    const globalFilterStatus  = document.getElementById('global-filter-status');
    const globalPerPage       = document.getElementById('global-per-page');
    const globalSearchCount   = document.getElementById('global-search-count');
    const globalSpeedTag      = document.getElementById('global-search-speed-tag');
    const globalTableBody     = document.getElementById('global-search-table-body');
    const globalPaginationInfo= document.getElementById('global-pagination-info');
    const btnGlobalPrevPage   = document.getElementById('btn-global-prev-page');
    const btnGlobalNextPage   = document.getElementById('btn-global-next-page');

    let globalSearchState = {
        page: 1,
        perPage: 15,
        totalPages: 1,
        query: '',
        debounceTimer: null
    };

    function loadGlobalSearch() {
        if (!globalTableBody) return;

        const q = globalSearchInput ? globalSearchInput.value.trim() : '';
        const h = globalFilterHost ? globalFilterHost.value : 'all';
        const u = globalFilterUser ? globalFilterUser.value : 'all';
        const algo = globalFilterAlgo ? globalFilterAlgo.value : 'all';
        const status = globalFilterStatus ? globalFilterStatus.value : 'all';
        const perPage = globalPerPage ? parseInt(globalPerPage.value) : 15;

        const params = new URLSearchParams({
            q: q,
            host: h,
            user: u,
            algo: algo,
            status: status,
            page: globalSearchState.page,
            per_page: perPage
        });

        fetch(`/api/search/global?${params.toString()}`)
            .then(r => r.json())
            .then(data => {
                if (globalSpeedTag) globalSpeedTag.innerHTML = `<i class="fa-solid fa-bolt"></i> ${data.elapsed_ms}ms`;
                if (globalSearchCount) globalSearchCount.textContent = data.total_matches;
                
                globalSearchState.totalPages = data.total_pages;
                if (globalPaginationInfo) globalPaginationInfo.textContent = `Page ${data.page} of ${data.total_pages} (${data.total_matches} items)`;

                if (btnGlobalPrevPage) btnGlobalPrevPage.disabled = (data.page <= 1);
                if (btnGlobalNextPage) btnGlobalNextPage.disabled = (data.page >= data.total_pages);

                renderGlobalSearchRows(data.results || []);
            })
            .catch(err => {
                if (globalTableBody) globalTableBody.innerHTML = `<tr><td colspan="10" class="text-center" style="padding:20px;color:var(--danger);">Error searching database: ${err.message}</td></tr>`;
            });
    }

    window.copyTextToClipboard = function(text, btn) {
        if (!text) return;
        if (!navigator.clipboard) {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
        } else {
            navigator.clipboard.writeText(text);
        }
        if (btn) {
            const origHTML = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-check" style="color:var(--success);"></i> Copied!';
            setTimeout(() => { btn.innerHTML = origHTML; }, 2000);
        }
    };

    function renderGlobalSearchRows(rows) {
        if (!globalTableBody) return;
        if (rows.length === 0) {
            globalTableBody.innerHTML = '<tr><td colspan="10" class="text-center" style="padding:32px;color:var(--text-muted);"><i class="fa-solid fa-magnifying-glass" style="font-size:1.6rem;margin-bottom:8px;display:block;opacity:0.4;"></i> No matching SSH key records found in local database.</td></tr>';
            return;
        }

        let html = '';
        rows.forEach((r, idx) => {
            const algoClass = (r.algorithm || '').toLowerCase().includes('ed25519') ? 'ed25519' : ((r.algorithm || '').toLowerCase().includes('ecdsa') ? 'ecdsa' : 'rsa');
            const isDup = r.is_duplicate;
            const canCopyFull = r.can_copy_full;

            const copyBtnHtml = canCopyFull
                ? `<button class="btn btn-outline btn-xs" onclick="copyTextToClipboard(\`${escapeJS(r.raw_key)}\`, this)" title="Copy Full Unmasked SSH Key" style="margin-right:4px;">
                    <i class="fa-solid fa-copy"></i> Copy Key
                   </button>`
                : '';

            html += `
                <tr>
                    <td><strong>#${((globalSearchState.page - 1) * globalSearchState.perPage) + idx + 1}</strong></td>
                    <td><span class="badge badge-primary"><i class="fa-solid fa-server"></i> ${escapeHtml(r.host)}</span></td>
                    <td><code>${escapeHtml(r.user)}</code></td>
                    <td><span style="font-family:var(--font-mono);font-size:11px;color:var(--text-dim);">${escapeHtml(r.home_dir)}</span></td>
                    <td><span class="key-algo-badge ${algoClass}">${escapeHtml(r.algorithm)}</span></td>
                    <td><span class="comment-chip"><i class="fa-solid fa-laptop-code"></i> ${escapeHtml(r.comment)}</span></td>
                    <td style="max-width:280px;">
                        <code style="font-size:10.5px;color:var(--text-muted);display:block;margin-bottom:4px;">${escapeHtml(r.fingerprint)}</code>
                        <div style="font-family:var(--font-mono);font-size:10px;color:var(--primary);background:rgba(0,0,0,0.3);padding:4px 6px;border-radius:4px;word-break:break-all;max-height:60px;overflow-y:auto;user-select:all;border:1px solid rgba(255,255,255,0.06);">
                            ${escapeHtml(r.raw_key)}
                        </div>
                    </td>
                    <td>${isDup ? '<span class="badge badge-warning"><i class="fa-solid fa-copy"></i> Duplicate</span>' : '<span class="badge badge-success"><i class="fa-solid fa-check"></i> Active</span>'}</td>
                    <td><span style="font-size:10.5px;color:var(--text-dim);">${escapeHtml(r.last_synced_at || 'Just now')}</span></td>
                    <td style="text-align:right;white-space:nowrap;display:flex;gap:4px;justify-content:flex-end;">
                        ${copyBtnHtml}
                        <button class="btn btn-primary btn-xs" onclick="openKeyInspectorModal('${r.host}', '${r.user}')" title="Inspect user keys">
                            <i class="fa-solid fa-magnifying-glass"></i> Inspect
                        </button>
                    </td>
                </tr>`;
        });

        globalTableBody.innerHTML = html;
    }

    if (globalSearchInput) {
        globalSearchInput.addEventListener('input', () => {
            clearTimeout(globalSearchState.debounceTimer);
            globalSearchState.page = 1;
            globalSearchState.debounceTimer = setTimeout(loadGlobalSearch, 150);
        });
    }

    if (globalFilterHost) globalFilterHost.addEventListener('change', () => { globalSearchState.page = 1; loadGlobalSearch(); });
    if (globalFilterUser) globalFilterUser.addEventListener('change', () => { globalSearchState.page = 1; loadGlobalSearch(); });
    if (globalFilterAlgo) globalFilterAlgo.addEventListener('change', () => { globalSearchState.page = 1; loadGlobalSearch(); });
    if (globalFilterStatus) globalFilterStatus.addEventListener('change', () => { globalSearchState.page = 1; loadGlobalSearch(); });
    if (globalPerPage) globalPerPage.addEventListener('change', () => { globalSearchState.perPage = parseInt(globalPerPage.value); globalSearchState.page = 1; loadGlobalSearch(); });

    if (btnGlobalPrevPage) {
        btnGlobalPrevPage.addEventListener('click', () => {
            if (globalSearchState.page > 1) {
                globalSearchState.page--;
                loadGlobalSearch();
            }
        });
    }

    if (btnGlobalNextPage) {
        btnGlobalNextPage.addEventListener('click', () => {
            if (globalSearchState.page < globalSearchState.totalPages) {
                globalSearchState.page++;
                loadGlobalSearch();
            }
        });
    }

    const syncLastGlobalTime   = document.getElementById('sync-last-global-time');
    const syncTotalKeysCount   = document.getElementById('sync-total-keys-count');
    const syncTotalHostsCount  = document.getElementById('sync-total-hosts-count');
    const syncTotalUsersCount  = document.getElementById('sync-total-users-count');
    const syncDuplicateKeysCount= document.getElementById('sync-duplicate-keys-count');
    const syncSingleHostSelect = document.getElementById('sync-single-host-select');
    const syncOperatorName     = document.getElementById('sync-operator-name');
    const syncJobStatusBadge   = document.getElementById('sync-job-status-badge');
    const syncExecutionLog     = document.getElementById('sync-execution-log');
    const syncHistoryTableBody = document.getElementById('sync-history-table-body');
    const btnSyncAllServers    = document.getElementById('btn-sync-all-servers');
    const btnSyncSingleHost    = document.getElementById('btn-sync-single-host');
    const btnSyncRefreshMetrics= document.getElementById('btn-sync-refresh-metrics');

    const syncChangesTableBody = document.getElementById('sync-changes-table-body');
    const changeFilterType     = document.getElementById('change-filter-type');
    const btnRefreshChangeLogs = document.getElementById('btn-refresh-change-logs');

    function loadSyncChangeLogs() {
        if (!syncChangesTableBody) return;
        const changeType = changeFilterType ? changeFilterType.value : 'all';

        fetch('/api/sync/changes?change_type=' + encodeURIComponent(changeType))
            .then(r => r.json())
            .then(logs => {
                if (logs.length === 0) {
                    syncChangesTableBody.innerHTML = '<tr><td colspan="7" class="text-center" style="padding:16px;color:var(--text-muted);">No infrastructure changes recorded yet.</td></tr>';
                    return;
                }

                let html = '';
                logs.forEach(c => {
                    let catBadge = '<span class="badge badge-info">INFO</span>';
                    if (c.change_type === 'NEW_USER') catBadge = '<span class="badge badge-success"><i class="fa-solid fa-user-plus"></i> NEW USER</span>';
                    else if (c.change_type === 'KEY_ADDED') catBadge = '<span class="badge badge-success"><i class="fa-solid fa-key"></i> KEY ADDED</span>';
                    else if (c.change_type === 'KEY_REMOVED') catBadge = '<span class="badge badge-warning"><i class="fa-solid fa-key"></i> KEY REMOVED</span>';
                    else if (c.change_type === 'USER_REMOVED') catBadge = '<span class="badge badge-danger"><i class="fa-solid fa-user-minus"></i> USER REMOVED</span>';
                    else if (c.change_type === 'SERVER_UNREACHABLE') catBadge = '<span class="badge badge-danger"><i class="fa-solid fa-triangle-exclamation"></i> UNREACHABLE</span>';

                    html += `
                        <tr>
                            <td><span style="font-size:11px;color:var(--text-dim);">${escapeHtml(c.timestamp)}</span></td>
                            <td><code>${escapeHtml(c.job_id)}</code></td>
                            <td>${escapeHtml(c.operator_name || 'Admin')}</td>
                            <td><span class="badge badge-primary"><i class="fa-solid fa-server"></i> ${escapeHtml(c.host)}</span></td>
                            <td><code>${escapeHtml(c.user)}</code></td>
                            <td>${catBadge}</td>
                            <td><span style="font-size:12px;color:var(--text-main);">${escapeHtml(c.description)}</span></td>
                        </tr>`;
                });
                syncChangesTableBody.innerHTML = html;
            })
            .catch(() => {
                syncChangesTableBody.innerHTML = '<tr><td colspan="7" class="text-center" style="padding:16px;color:var(--danger);">Error loading change audit logs.</td></tr>';
            });
    }

    if (changeFilterType) changeFilterType.addEventListener('change', loadSyncChangeLogs);
    if (btnRefreshChangeLogs) btnRefreshChangeLogs.addEventListener('click', loadSyncChangeLogs);

    function loadSyncDashboard() {
        fetch('/api/sync/status')
            .then(r => r.json())
            .then(data => {
                if (syncLastGlobalTime) syncLastGlobalTime.textContent = data.last_global_sync;
                if (syncTotalKeysCount) syncTotalKeysCount.textContent = data.total_keys;
                if (syncTotalHostsCount) syncTotalHostsCount.textContent = data.total_hosts;
                if (syncTotalUsersCount) syncTotalUsersCount.textContent = data.total_users;
                if (syncDuplicateKeysCount) syncDuplicateKeysCount.textContent = data.duplicate_keys;

                updateHeaderLastSynced(data.last_global_sync);
                renderSyncHistoryTable(data.recent_history || []);
                loadSyncChangeLogs();
            })
            .catch(() => {});
    }

    function renderSyncHistoryTable(history) {
        if (!syncHistoryTableBody) return;
        if (history.length === 0) {
            syncHistoryTableBody.innerHTML = '<tr><td colspan="9" class="text-center" style="padding:16px;color:var(--text-muted);">No sync jobs run yet.</td></tr>';
            return;
        }

        let html = '';
        history.forEach(h => {
            let statusBadge = '<span class="badge badge-success">SUCCESS</span>';
            if (h.status === 'PARTIAL_SUCCESS') {
                statusBadge = `<span class="badge badge-warning" title="${escapeHtml(h.failures || 'Some hosts failed')}">PARTIAL SUCCESS</span>`;
            } else if (h.status === 'FAILED') {
                statusBadge = `<span class="badge badge-danger" title="${escapeHtml(h.failures || 'Execution failed')}">FAILED</span>`;
            }

            const failDetail = h.failures ? `<div style="font-size:10px;color:var(--danger);margin-top:2px;">${escapeHtml(h.failures)}</div>` : '';

            html += `
                <tr>
                    <td><code>${escapeHtml(h.job_id)}</code></td>
                    <td><span style="font-size:11px;color:var(--text-dim);">${escapeHtml(h.started_at)}</span></td>
                    <td><span class="badge badge-info" style="text-transform:uppercase;">${escapeHtml(h.sync_mode)}</span></td>
                    <td><strong style="color:var(--primary);">${escapeHtml(h.target_hosts)}</strong></td>
                    <td>${escapeHtml(h.operator_name || 'Admin')}</td>
                    <td>${h.users_scanned || 0} users</td>
                    <td><strong style="color:var(--success);">${h.keys_added || 0} keys</strong></td>
                    <td>${h.execution_time_sec ? h.execution_time_sec + 's' : '--'}</td>
                    <td>${statusBadge}${failDetail}</td>
                </tr>`;
        });
        syncHistoryTableBody.innerHTML = html;
    }

    function triggerSyncJob(mode, hosts) {
        const opName = syncOperatorName ? syncOperatorName.value.trim() || 'Admin' : 'Admin';
        
        if (syncJobStatusBadge) {
            syncJobStatusBadge.className = 'badge badge-warning';
            syncJobStatusBadge.textContent = 'RUNNING';
        }
        if (syncExecutionLog) {
            syncExecutionLog.textContent = `[${ts()}] Initiating background ${mode} synchronization for ${Array.isArray(hosts) ? hosts.join(',') : hosts}...\n`;
        }

        fetch('/api/sync/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sync_mode: mode,
                target_hosts: hosts,
                operator_name: opName
            })
        })
        .then(r => r.json())
        .then(data => {
            const jobId = data.job_id;
            const interval = setInterval(() => {
                fetch(`/api/jobs/${jobId}`)
                    .then(r => r.json())
                    .then(job => {
                        if (syncExecutionLog) {
                            syncExecutionLog.textContent = job.logs || 'Synchronizing with remote hosts...';
                            syncExecutionLog.scrollTop = syncExecutionLog.scrollHeight;
                        }

                        if (job.status === 'SUCCESS') {
                            clearInterval(interval);
                            if (syncJobStatusBadge) {
                                syncJobStatusBadge.className = 'badge badge-success';
                                syncJobStatusBadge.textContent = 'SUCCESS';
                            }
                            loadSyncDashboard();
                            loadGlobalSearch();
                            loadAccessMatrix(false);
                        } else if (job.status === 'PARTIAL_SUCCESS') {
                            clearInterval(interval);
                            if (syncJobStatusBadge) {
                                syncJobStatusBadge.className = 'badge badge-warning';
                                syncJobStatusBadge.textContent = 'PARTIAL SUCCESS';
                            }
                            loadSyncDashboard();
                            loadGlobalSearch();
                        } else if (job.status === 'FAILED') {
                            clearInterval(interval);
                            if (syncJobStatusBadge) {
                                syncJobStatusBadge.className = 'badge badge-danger';
                                syncJobStatusBadge.textContent = 'FAILED';
                            }
                            loadSyncDashboard();
                        }
                    })
                    .catch(() => {});
            }, 1500);
        })
        .catch(err => {
            if (syncJobStatusBadge) {
                syncJobStatusBadge.className = 'badge badge-danger';
                syncJobStatusBadge.textContent = 'ERROR';
            }
            if (syncExecutionLog) syncExecutionLog.textContent += `[${ts()}] Error: ${err.message}\n`;
        });
    }

    if (btnSyncAllServers) {
        btnSyncAllServers.addEventListener('click', () => triggerSyncJob('full', ['all']));
    }

    if (btnSyncSingleHost) {
        btnSyncSingleHost.addEventListener('click', () => {
            const h = syncSingleHostSelect ? syncSingleHostSelect.value : '';
            if (!h) { alert('Please select a server host to sync.'); return; }
            triggerSyncJob('single', [h]);
        });
    }

    if (btnSyncRefreshMetrics) {
        btnSyncRefreshMetrics.addEventListener('click', () => {
            loadSyncDashboard();
            loadGlobalSearch();
        });
    }

    /* ============================================================
       AUTHENTICATION & RBAC STATE
    ============================================================ */
    const loginPortal        = document.getElementById('login-portal');
    const formLogin          = document.getElementById('form-login');
    const loginUsernameInput = document.getElementById('login-username');
    const loginPasswordInput = document.getElementById('login-password');
    const loginErrorMsg      = document.getElementById('login-error-msg');
    const btnSubmitLogin     = document.getElementById('btn-submit-login');

    const headerUserBadge    = document.getElementById('header-user-badge');
    const userDisplayName    = document.getElementById('user-display-name');
    const userRoleBadge      = document.getElementById('user-role-badge');
    const btnHeaderLogout    = document.getElementById('btn-header-logout');

    let currentUser          = null;

    function checkAuthSession() {
        fetch('/api/auth/me')
            .then(r => r.json())
            .then(data => {
                if (data.authenticated && data.user) {
                    currentUser = data.user;
                    if (loginPortal) loginPortal.style.display = 'none';
                    if (headerUserBadge) headerUserBadge.style.display = 'flex';
                    if (userDisplayName) userDisplayName.textContent = currentUser.full_name || currentUser.username;
                    if (userRoleBadge) {
                        userRoleBadge.textContent = currentUser.role.toUpperCase();
                        userRoleBadge.className = currentUser.role === 'admin' ? 'badge badge-primary' : 'badge badge-info';
                    }
                    applyRolePermissions(currentUser);
                    initDashboard();
                } else {
                    currentUser = null;
                    if (loginPortal) loginPortal.style.display = 'flex';
                    if (headerUserBadge) headerUserBadge.style.display = 'none';
                }
            })
            .catch(() => {
                if (loginPortal) loginPortal.style.display = 'flex';
            });
    }

    if (formLogin) {
        formLogin.addEventListener('submit', (e) => {
            e.preventDefault();
            const username = loginUsernameInput ? loginUsernameInput.value.trim() : '';
            const password = loginPasswordInput ? loginPasswordInput.value.trim() : '';

            if (!username || !password) {
                if (loginErrorMsg) loginErrorMsg.textContent = 'Please enter both username and password.';
                return;
            }

            if (btnSubmitLogin) {
                btnSubmitLogin.disabled = true;
                btnSubmitLogin.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Authenticating...';
            }
            if (loginErrorMsg) loginErrorMsg.textContent = '';

            fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            })
            .then(r => r.json())
            .then(data => {
                if (btnSubmitLogin) {
                    btnSubmitLogin.disabled = false;
                    btnSubmitLogin.innerHTML = '<i class="fa-solid fa-right-to-bracket"></i> Log In to Dashboard';
                }
                if (data.error) {
                    if (loginErrorMsg) loginErrorMsg.textContent = data.error;
                } else {
                    currentUser = data.user;
                    if (loginPortal) loginPortal.style.display = 'none';
                    if (headerUserBadge) headerUserBadge.style.display = 'flex';
                    if (userDisplayName) userDisplayName.textContent = currentUser.full_name || currentUser.username;
                    if (userRoleBadge) {
                        userRoleBadge.textContent = currentUser.role.toUpperCase();
                        userRoleBadge.className = currentUser.role === 'admin' ? 'badge badge-primary' : 'badge badge-info';
                    }
                    applyRolePermissions(currentUser);
                    initDashboard();
                }
            })
            .catch(err => {
                if (btnSubmitLogin) {
                    btnSubmitLogin.disabled = false;
                    btnSubmitLogin.innerHTML = '<i class="fa-solid fa-right-to-bracket"></i> Log In to Dashboard';
                }
                if (loginErrorMsg) loginErrorMsg.textContent = 'Authentication error: ' + err.message;
            });
        });
    }

    if (btnHeaderLogout) {
        btnHeaderLogout.addEventListener('click', () => {
            fetch('/api/auth/logout', { method: 'POST' })
                .then(() => {
                    currentUser = null;
                    if (loginPortal) loginPortal.style.display = 'flex';
                    if (headerUserBadge) headerUserBadge.style.display = 'none';
                    if (loginUsernameInput) loginUsernameInput.value = '';
                    if (loginPasswordInput) loginPasswordInput.value = '';
                });
        });
    }

    function applyRolePermissions(user) {
        const isDev = (user && user.role === 'developer');
        const perms = (user && user.permissions) || [];
        const canWrite = perms.includes('write:keys');
        const canManageServers = perms.includes('manage:servers');

        const btnOpenAddServer = document.getElementById('btn-open-add-server-modal');
        if (btnOpenAddServer) btnOpenAddServer.style.display = canManageServers ? 'inline-flex' : 'none';

        if (btnAddKey) btnAddKey.disabled = !canWrite;
        if (btnRemoveKey) btnRemoveKey.disabled = !canWrite;
        if (btnPurgeUser) btnPurgeUser.disabled = !canWrite;
        if (btnDisableUser) btnDisableUser.disabled = !canWrite;

        const writeNotice = document.getElementById('rbac-read-only-banner');
        if (isDev) {
            if (!writeNotice) {
                const banner = document.createElement('div');
                banner.id = 'rbac-read-only-banner';
                banner.style.cssText = 'background:rgba(234,179,8,0.1);border:1px solid rgba(234,179,8,0.3);color:#eab308;padding:10px 16px;border-radius:8px;font-size:12px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:10px;grid-column:1/-1;';
                banner.innerHTML = '<i class="fa-solid fa-eye"></i> <span><strong>Developer Read-Only Mode:</strong> Key modifications, server administration, and unmasked keys are restricted to Administrators.</span>';
                const statsRow = document.getElementById('stats-row');
                if (statsRow && statsRow.parentNode) {
                    statsRow.parentNode.insertBefore(banner, statsRow.nextSibling);
                }
            }
        } else {
            if (writeNotice) writeNotice.remove();
        }
    }

    function initDashboard() {
        fetchInventory();
        loadGlobalSearch();
    }

    /* ============================================================
       HELPERS
    ============================================================ */
    function ts() {
        return new Date().toLocaleTimeString('en-IN', { hour12: false });
    }

    /* ============================================================
       INIT
    ============================================================ */
    checkAuthSession();
});
