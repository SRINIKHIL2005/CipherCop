import React, { useState } from "react";

function App() {
  const [website, setWebsite] = useState("");
  const [appName, setAppName] = useState("");
  const [packageName, setPackageName] = useState("");
  const [description, setDescription] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyzeWebsite = async () => {
    setLoading(true);
    setResult(null);
    const res = await fetch("http://localhost:5000/analyze/website", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: website }),
    });
    setResult(await res.json());
    setLoading(false);
  };

  const analyzeApp = async () => {
    setLoading(true);
    setResult(null);
    const res = await fetch("http://localhost:5000/analyze/app", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ app_name: appName, package: packageName, description }),
    });
    setResult(await res.json());
    setLoading(false);
  };

  return (
    <div style={{ maxWidth: 600, margin: "auto", padding: 20 }}>
      <h2>Fraudulent Content Detector</h2>
      <div style={{ marginBottom: 30 }}>
        <h3>Analyze Website</h3>
        <input
          type="text"
          placeholder="Enter website URL"
          value={website}
          onChange={e => setWebsite(e.target.value)}
          style={{ width: "80%", marginRight: 10 }}
        />
        <button onClick={analyzeWebsite} disabled={loading || !website}>
          Analyze Website
        </button>
      </div>
      <div style={{ marginBottom: 30 }}>
        <h3>Analyze Mobile App</h3>
        <input
          type="text"
          placeholder="App Name"
          value={appName}
          onChange={e => setAppName(e.target.value)}
          style={{ width: "30%", marginRight: 10 }}
        />
        <input
          type="text"
          placeholder="Package Name"
          value={packageName}
          onChange={e => setPackageName(e.target.value)}
          style={{ width: "30%", marginRight: 10 }}
        />
        <input
          type="text"
          placeholder="Description"
          value={description}
          onChange={e => setDescription(e.target.value)}
          style={{ width: "30%", marginRight: 10 }}
        />
        <button onClick={analyzeApp} disabled={loading || (!appName && !packageName && !description)}>
          Analyze App
        </button>
      </div>
      {loading && <div>Analyzing...</div>}
      {result && (
        <div style={{ background: "#f0f0f0", padding: 20, borderRadius: 8 }}>
          <h4>Result:</h4>
          <pre style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

export default App;
