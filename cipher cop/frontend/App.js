import React, { useState, useEffect } from 'react';
import './index.css';

const API_BASE = 'http://localhost:5000';

const CipherCopDashboard = () => {
  const [activeTab, setActiveTab] = useState('website');
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  // Website Analysis State
  const [websiteUrl, setWebsiteUrl] = useState('');

  // App Analysis State  
  const [appName, setAppName] = useState('');
  const [appPackage, setAppPackage] = useState('');
  const [appVersion, setAppVersion] = useState('');

  // APK Analysis State
  const [apkFile, setApkFile] = useState(null);
  const [dragOver, setDragOver] = useState(false);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await fetch(`${API_BASE}/stats`);
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  };

  const analyzeWebsite = async () => {
    if (!websiteUrl.trim()) return;

    setLoading(true);
    setResult(null);

    try {
      const response = await fetch(`${API_BASE}/analyze/website`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: websiteUrl.trim() })
      });

      const data = await response.json();
      setResult({
        type: 'website',
        url: websiteUrl,
        ...data
      });
    } catch (error) {
      setResult({
        type: 'website',
        url: websiteUrl,
        error: error.message
      });
    } finally {
      setLoading(false);
    }
  };

  const analyzeApp = async () => {
    if (!appName.trim()) return;

    setLoading(true);
    setResult(null);

    try {
      const response = await fetch(`${API_BASE}/analyze/app`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          appName: appName.trim(),
          packageName: appPackage.trim(),
          version: appVersion.trim()
        })
      });

      const data = await response.json();
      setResult({
        type: 'app',
        appName: appName,
        ...data
      });
    } catch (error) {
      setResult({
        type: 'app',
        appName: appName,
        error: error.message
      });
    } finally {
      setLoading(false);
    }
  };

  const analyzeAPK = async () => {
    if (!apkFile) return;

    setLoading(true);
    setResult(null);

    try {
      const formData = new FormData();
  formData.append('file', apkFile);

      const response = await fetch(`${API_BASE}/analyze/apk-file`, {
        method: 'POST',
        body: formData
      });

      const data = await response.json();
      setResult({
        type: 'apk',
        fileName: apkFile.name,
        fileSize: apkFile.size,
        ...data
      });
    } catch (error) {
      setResult({
        type: 'apk',
        fileName: apkFile.name,
        error: error.message
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    
    const files = Array.from(e.dataTransfer.files);
    const apkFile = files.find(file => 
      file.name.toLowerCase().endsWith('.apk') || 
      file.type === 'application/vnd.android.package-archive'
    );
    
    if (apkFile) {
      setApkFile(apkFile);
    } else {
      alert('Please drop a valid APK file');
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file && (file.name.toLowerCase().endsWith('.apk') || 
                 file.type === 'application/vnd.android.package-archive')) {
      setApkFile(file);
    } else {
      alert('Please select a valid APK file');
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getResultColor = (classification) => {
    switch (classification?.toUpperCase()) {
      case 'MALICIOUS':
      case 'FRAUDULENT':
        return '#dc3545';
      case 'SUSPICIOUS':
        return '#fd7e14';
      case 'LEGITIMATE':
      case 'BENIGN':
        return '#198754';
      default:
        return '#6c757d';
    }
  };

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>🛡️ CipherCop Security Dashboard</h1>
        <div className="stats-bar">
          {stats && (
            <>
              <div className="stat">
                <span className="stat-label">Total Scans:</span>
                <span className="stat-value">{stats.total_threats || 0}</span>
              </div>
              <div className="stat">
                <span className="stat-label">Threats Blocked:</span>
                <span className="stat-value">{stats.blocked_threats || 0}</span>
              </div>
              <div className="stat">
                <span className="stat-label">ML Model:</span>
                <span className="stat-value">{stats.ml_model_loaded ? '✅' : '❌'}</span>
              </div>
            </>
          )}
        </div>
      </header>

      <div className="tabs">
        <button 
          className={`tab ${activeTab === 'website' ? 'active' : ''}`}
          onClick={() => setActiveTab('website')}
        >
          🌐 Website Security
        </button>
        <button 
          className={`tab ${activeTab === 'app' ? 'active' : ''}`}
          onClick={() => setActiveTab('app')}
        >
          📱 App Analysis
        </button>
        <button 
          className={`tab ${activeTab === 'apk' ? 'active' : ''}`}
          onClick={() => setActiveTab('apk')}
        >
          📦 APK Malware Scan
        </button>
      </div>

      <div className="content">
        {/* Website Analysis Tab */}
        {activeTab === 'website' && (
          <div className="analysis-section">
            <h2>Website Security Analysis</h2>
            <div className="input-group">
              <input
                type="url"
                placeholder="Enter website URL (e.g., https://example.com)"
                value={websiteUrl}
                onChange={(e) => setWebsiteUrl(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && analyzeWebsite()}
              />
              <button onClick={analyzeWebsite} disabled={loading || !websiteUrl.trim()}>
                {loading ? 'Analyzing...' : 'Analyze Website'}
              </button>
            </div>
            <div className="features-info">
              <p>🔍 <strong>Analysis includes:</strong> XGBoost ML model (30+ features), Google Safe Browsing, Domain analysis, SSL verification, Phishing patterns</p>
            </div>
          </div>
        )}

        {/* App Analysis Tab */}
        {activeTab === 'app' && (
          <div className="analysis-section">
            <h2>Mobile App Security Analysis</h2>
            <div className="input-group">
              <input
                type="text"
                placeholder="App Name (e.g., WhatsApp)"
                value={appName}
                onChange={(e) => setAppName(e.target.value)}
              />
              <input
                type="text"
                placeholder="Package Name (e.g., com.whatsapp)"
                value={appPackage}
                onChange={(e) => setAppPackage(e.target.value)}
              />
              <input
                type="text"
                placeholder="Version (optional)"
                value={appVersion}
                onChange={(e) => setAppVersion(e.target.value)}
              />
              <label className="file-select-btn">
                Upload APK for deeper scan
                <input
                  type="file"
                  accept=".apk,application/vnd.android.package-archive"
                  onChange={(e) => {
                    const f = e.target.files[0];
                    if (f) setApkFile(f);
                  }}
                  hidden
                />
              </label>
              <button onClick={() => (apkFile ? analyzeAPK() : analyzeApp())} disabled={loading || (!appName.trim() && !apkFile)}>
                {loading ? 'Analyzing...' : (apkFile ? 'Scan APK & Analyze' : 'Analyze App')}
              </button>
            </div>
            <div className="features-info">
              <p>📱 <strong>Analysis includes:</strong> App store verification, Permission analysis, Known malware signatures, Reputation scoring</p>
            </div>
          </div>
        )}

        {/* APK Analysis Tab */}
        {activeTab === 'apk' && (
          <div className="analysis-section">
            <h2>APK Malware Detection</h2>
            <div 
              className={`file-drop-zone ${dragOver ? 'drag-over' : ''}`}
              onDrop={handleDrop}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
            >
              {apkFile ? (
                <div className="file-selected">
                  <div className="file-info">
                    <div className="file-icon">📦</div>
                    <div className="file-details">
                      <div className="file-name">{apkFile.name}</div>
                      <div className="file-size">{formatFileSize(apkFile.size)}</div>
                    </div>
                    <button 
                      className="remove-file"
                      onClick={() => setApkFile(null)}
                    >
                      ✕
                    </button>
                  </div>
                  <button 
                    className="analyze-btn"
                    onClick={analyzeAPK} 
                    disabled={loading}
                  >
                    {loading ? 'Scanning APK...' : 'Scan for Malware'}
                  </button>
                </div>
              ) : (
                <div className="drop-instructions">
                  <div className="drop-icon">📁</div>
                  <p><strong>Drop APK file here</strong></p>
                  <p>or</p>
                  <label className="file-select-btn">
                    Choose APK File
                    <input 
                      type="file" 
                      accept=".apk,application/vnd.android.package-archive"
                      onChange={handleFileSelect}
                      hidden
                    />
                  </label>
                  <p className="file-info-text">Supports .apk files up to 50MB</p>
                </div>
              )}
            </div>
            <div className="features-info">
              <p>🔍 <strong>APK Analysis includes:</strong> XGBoost ML model (215+ features), Permission analysis, API call patterns, File structure analysis, Known malware signatures</p>
            </div>
          </div>
        )}

        {/* Results Display */}
        {result && (
          <div className="results-section">
            <h3>Analysis Results</h3>
            {result.error ? (
              <div className="result error">
                <h4>❌ Analysis Error</h4>
                <p>{result.error}</p>
              </div>
            ) : (
              <div 
                className="result"
                style={{ borderLeft: `4px solid ${getResultColor(result.classification || result.verdict)}` }}
              >
                {/* Website Results */}
                {result.type === 'website' && (
                  <>
                    <div className="result-header">
                      <h4 style={{ color: getResultColor(result.classification || result.verdict) }}>
                        {result.classification || result.verdict || 'UNKNOWN'}
                      </h4>
                      <div className="confidence">
                        Confidence: {result.confidence_score || result.confidence || 0}%
                      </div>
                    </div>
                    <div className="result-details">
                      <p><strong>URL:</strong> {result.url}</p>
                      {result.threat_sources?.length > 0 && (
                        <p><strong>Detection Sources:</strong> {result.threat_sources.join(', ')}</p>
                      )}
                      {result.analysis_summary && (
                        <div className="analysis-summary">
                          <p><strong>Risk Score:</strong> {result.analysis_summary.combined_risk_score || 'N/A'}</p>
                          <p><strong>Safe Browsing:</strong> {result.analysis_summary.safe_browsing_threat ? '⚠️ Threat detected' : '✅ Clean'}</p>
                          <p><strong>ML Detection:</strong> {result.analysis_summary.ml_phishing_detected ? '🤖 ML flagged' : '✅ ML clean'}</p>
                        </div>
                      )}
                    </div>
                  </>
                )}

                {/* App Results */}
                {result.type === 'app' && (
                  <>
                    <div className="result-header">
                      <h4 style={{ color: getResultColor(result.classification || result.verdict) }}>
                        {result.classification || result.verdict || 'UNKNOWN'}
                      </h4>
                      <div className="confidence">
                        Risk Score: {result.risk_score || 0}%
                      </div>
                    </div>
                    <div className="result-details">
                      <p><strong>App:</strong> {result.appName}</p>
                      {result.threat_indicators?.length > 0 && (
                        <p><strong>Threat Indicators:</strong> {result.threat_indicators.join(', ')}</p>
                      )}
                      {result.permissions && (
                        <p><strong>Suspicious Permissions:</strong> {result.permissions.join(', ')}</p>
                      )}
                    </div>
                  </>
                )}

                {/* APK Results */}
                {result.type === 'apk' && (
                  <>
                    <div className="result-header">
                      <h4 style={{ color: getResultColor(result.classification || result.verdict) }}>
                        {result.classification || result.verdict || 'UNKNOWN'}
                      </h4>
                      <div className="confidence">
                        Confidence: {result.confidence_score || result.confidence || 0}%
                      </div>
                    </div>
                    <div className="result-details">
                      <p><strong>File:</strong> {result.fileName}</p>
                      <p><strong>Size:</strong> {formatFileSize(result.fileSize)}</p>
                      {result.features_analyzed && (
                        <p><strong>Features Analyzed:</strong> {result.features_analyzed}</p>
                      )}
                      {result.threat_indicators?.length > 0 && (
                        <p><strong>Threat Indicators:</strong> {result.threat_indicators.join(', ')}</p>
                      )}
                      {result.analysis_summary && (
                        <div className="analysis-summary">
                          <p><strong>ML Model:</strong> {result.analysis_summary.ml_model_used || 'XGBoost'}</p>
                          <p><strong>Processing Time:</strong> {result.analysis_summary.processing_time || 'N/A'}ms</p>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default CipherCopDashboard;
