import React, { useState, useEffect, useRef } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Legend
} from 'recharts';
import { 
  ShieldAlert, Activity, Users, Globe, Terminal, Server, Key, Eye, Clock, 
  MapPin, AlertCircle, RefreshCw, X, ArrowUpRight, TrendingUp
} from 'lucide-react';
import './App.css';

// Country Coordinates Lookup for Leaflet Map
const COUNTRY_COORDS = {
  'US': [37.0902, -95.7129],
  'CN': [35.8617, 104.1954],
  'RU': [61.5240, 105.3188],
  'DE': [51.1657, 10.4515],
  'NL': [52.1326, 5.2913],
  'GB': [55.3781, -3.4360],
  'FR': [46.2276, 2.2137],
  'IN': [20.5937, 78.9629],
  'BR': [-14.2350, -51.9253],
  'UA': [48.3794, 31.1656],
  'JP': [36.2048, 138.2529],
  'CA': [56.1304, -106.3468],
  'AU': [-25.2744, 133.7751],
  'KR': [35.9078, 127.7669],
  'PL': [51.9194, 19.1451],
  'SG': [1.3521, 103.8198],
  'HK': [22.3964, 114.1095],
  'RO': [45.9432, 24.9668],
  'VN': [14.0583, 108.2772],
  'SE': [60.1282, 18.6435],
  'CH': [46.8182, 8.2275],
};

const MITRE_TECHNIQUES = [
  { id: 'T1110.001', name: 'Password Guessing' },
  { id: 'T1110.004', name: 'Credential Stuffing' },
  { id: 'T1552.001', name: 'Credentials in Files' },
  { id: 'T1059', name: 'Command & Scripting' },
  { id: 'T1496', name: 'Resource Hijacking' },
  { id: 'T1595.002', name: 'Vulnerability Scanning' },
  { id: 'T1213', name: 'Data Info Repositories' },
  { id: 'T1078', name: 'Valid Accounts' },
];

function App() {
  // Global Filters
  const [sensorFilter, setSensorFilter] = useState('all');
  const [timeFilter, setTimeFilter] = useState('24h');

  // Stats & Dashboard Data
  const [stats, setStats] = useState({
    total_events: 0,
    unique_ips: 0,
    ssh_events: 0,
    http_events: 0,
  });
  const [events, setEvents] = useState([]);
  const [topIps, setTopIps] = useState([]);
  const [topCredentials, setTopCredentials] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [sensorHealth, setSensorHealth] = useState([]);
  const [ipEnrichments, setIpEnrichments] = useState({});

  // UI state
  const [selectedIp, setSelectedIp] = useState(null);
  const [ipDetail, setIpDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);

  const handleGenerateReport = async () => {
    setIsGeneratingReport(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/reports/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      if (res.ok) {
        const data = await res.json();
        // Trigger download of this generated PDF report
        window.open(`${API_BASE}/api/v1/reports/${data.report_id}/download`, '_blank');
      } else {
        alert("Failed to generate report. Make sure database contains events.");
      }
    } catch (err) {
      console.error("Report trigger error:", err);
      alert("Error triggering report: " + err.message);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  // Map & chart refs
  const mapContainerRef = useRef(null);
  const mapRef = useRef(null);
  const markersGroupRef = useRef(null);

  // API Backend URL (resolves to same host, port 8000 via internal docker proxies or direct localhost)
  const API_BASE = window.location.port === '3000' 
    ? 'http://localhost:8000' 
    : `${window.location.protocol}//${window.location.hostname}:8000`;

  // Fetch Dashboard Stats & Feeds
  const fetchData = async () => {
    setIsRefreshing(true);
    try {
      // 1. Stats
      const statsRes = await fetch(`${API_BASE}/api/v1/stats`);
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      // 2. Events feed
      let eventsUrl = `${API_BASE}/api/v1/events?limit=80`;
      if (sensorFilter !== 'all') {
        eventsUrl += `&sensor_type=${sensorFilter}`;
      }
      const eventsRes = await fetch(eventsUrl);
      if (eventsRes.ok) {
        const eventsData = await eventsRes.json();
        setEvents(eventsData);

        // Fetch IP profile geo lookup for unique IPs in feed to plot map markers
        const uniqueIps = [...new Set(eventsData.map(e => e.source_ip))].slice(0, 15);
        for (const ip of uniqueIps) {
          if (!ipEnrichments[ip]) {
            fetchIpProfileForMap(ip);
          }
        }
      }

      // 3. Top Attacking IPs
      const ipsRes = await fetch(`${API_BASE}/api/v1/top-ips?limit=8`);
      if (ipsRes.ok) setTopIps(await ipsRes.json());

      // 4. Top Credentials
      const credsRes = await fetch(`${API_BASE}/api/v1/top-credentials?limit=8`);
      if (credsRes.ok) setTopCredentials(await credsRes.json());

      // 5. Campaigns Tracker
      const campaignsRes = await fetch(`${API_BASE}/api/v1/campaigns?limit=8`);
      if (campaignsRes.ok) setCampaigns(await campaignsRes.json());

      // 6. Sensor Health
      const sensorsRes = await fetch(`${API_BASE}/api/v1/sensors`);
      if (sensorsRes.ok) setSensorHealth(await sensorsRes.json());

    } catch (err) {
      console.error("Failed to fetch dashboard data:", err);
    } finally {
      setIsRefreshing(false);
    }
  };

  // Fetch individual IP profiles to plot on map
  const fetchIpProfileForMap = async (ip) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/ip/${ip}`);
      if (res.ok) {
        const data = await res.json();
        if (data.profile) {
          setIpEnrichments(prev => ({
            ...prev,
            [ip]: data.profile
          }));
        }
      }
    } catch (err) {
      console.debug("Failed IP details for marker plotting:", err);
    }
  };

  // Fetch detailed drawer information
  const handleIpClick = async (ip) => {
    setSelectedIp(ip);
    setDetailLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/ip/${ip}`);
      if (res.ok) {
        const data = await res.json();
        setIpDetail(data);
      }
    } catch (err) {
      console.error("Failed IP details for drawer:", err);
    } finally {
      setDetailLoading(false);
    }
  };

  // Initial and auto-refresh loop (30 seconds)
  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [sensorFilter, timeFilter]);

  // Leaflet Map Initialization and Marker Syncing
  useEffect(() => {
    if (!mapContainerRef.current) return;

    if (!mapRef.current) {
      // Map configuration
      const map = L.map(mapContainerRef.current, {
        zoomControl: true,
        attributionControl: false
      }).setView([25, 10], 2);

      // Dark style tiles
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 19
      }).addTo(map);

      mapRef.current = map;
      markersGroupRef.current = L.layerGroup().addTo(map);
    }

    const markersGroup = markersGroupRef.current;
    markersGroup.clearLayers();

    // Plot markers based on active IP enrichments
    Object.entries(ipEnrichments).forEach(([ip, profile]) => {
      const countryCode = profile.country_code;
      if (countryCode && COUNTRY_COORDS[countryCode]) {
        const baseCoords = COUNTRY_COORDS[countryCode];
        // Add random scatter offset to prevent overlapping markers on centroids
        const scatterCoords = [
          baseCoords[0] + (Math.random() - 0.5) * 1.5,
          baseCoords[1] + (Math.random() - 0.5) * 1.5
        ];

        const customIcon = L.divIcon({
          className: 'custom-map-marker',
          html: `<div style="
            width: 10px;
            height: 10px;
            background-color: ${profile.abuse_score > 50 ? '#ef4444' : '#00f2fe'};
            border-radius: 50%;
            box-shadow: 0 0 10px ${profile.abuse_score > 50 ? '#ef4444' : '#00f2fe'};
          "></div>`
        });

        const marker = L.marker(scatterCoords, { icon: customIcon })
          .bindPopup(`
            <div style="font-family: Outfit, sans-serif; font-size: 13px;">
              <b style="color: #00f2fe;">${ip}</b><br/>
              <b>Country:</b> ${profile.country || 'Unknown'}<br/>
              <b>ISP:</b> ${profile.isp || 'Unknown'}<br/>
              <b>Abuse Score:</b> ${profile.abuse_score}%
            </div>
          `);

        marker.on('click', () => {
          handleIpClick(ip);
        });

        markersGroup.addLayer(marker);
      }
    });

  }, [ipEnrichments]);

  // Format Timeline Data for Recharts
  const getTimelineData = () => {
    // Generate mock timeline hourly buckets based on events
    const hours = {};
    const now = new Date();

    for (let i = 23; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 60 * 60 * 1000);
      const label = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      hours[label] = { time: label, SSH: 0, HTTP: 0, Total: 0 };
    }

    events.forEach(e => {
      const date = new Date(e.timestamp);
      const label = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      // Find closest key in our hours dict
      const hourKeys = Object.keys(hours);
      const match = hourKeys.find(k => k.split(':')[0] === label.split(':')[0]);
      if (match) {
        hours[match][e.sensor_type]++;
        hours[match].Total++;
      }
    });

    return Object.values(hours);
  };

  // Compile MITRE Technique counts from current active events
  const getMitreTechCounts = () => {
    // Map current attack types/event types to MITRE Techniques for visualization
    const counts = {
      'T1110.001': 0, 'T1110.004': 0, 'T1552.001': 0, 'T1059': 0,
      'T1496': 0, 'T1595.002': 0, 'T1213': 0, 'T1078': 0
    };

    events.forEach(e => {
      if (e.sensor_type === 'SSH') {
        counts['T1110.001']++;
        if (e.ssh_commands && e.ssh_commands.length > 0) counts['T1059']++;
        // Check for minerd/resource hijack
        const cmdText = JSON.stringify(e.ssh_commands || []).toLowerCase();
        if (cmdText.includes('miner') || cmdText.includes('xmrig')) counts['T1496']++;
      } else if (e.sensor_type === 'HTTP') {
        const path = (e.http_path || '').toLowerCase();
        if (path.includes('.env') || path.includes('config.php')) counts['T1552.001']++;
        if (path.includes('.git')) counts['T1213']++;
        if (path.includes('admin') || path.includes('login') || path.includes('phpmyadmin')) counts['T1078']++;
        if (e.attack_type && e.attack_type.toLowerCase() === 'scan') counts['T1595.002']++;
      }
    });

    return counts;
  };

  const mitreCounts = getMitreTechCounts();

  return (
    <div className="app-container">
      {/* Top Header */}
      <header className="app-header">
        <div className="logo-section">
          <ShieldAlert size={28} style={{ color: 'var(--accent-cyan)' }} />
          <h1>HONEYSTACK</h1>
          <span>SOC Threat Feed</span>
        </div>

        <div className="filters-section">
          {/* Sensor Filter */}
          <select 
            value={sensorFilter} 
            onChange={(e) => setSensorFilter(e.target.value)} 
            className="filter-select"
          >
            <option value="all">All Sensors</option>
            <option value="SSH">SSH Sensors</option>
            <option value="HTTP">HTTP Sensors</option>
          </select>

          {/* Time Filter */}
          <select 
            value={timeFilter} 
            onChange={(e) => setTimeFilter(e.target.value)} 
            className="filter-select"
          >
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="all">All-Time</option>
          </select>

          {/* Refresh Button */}
          <button 
            onClick={fetchData} 
            className="filter-select" 
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
            disabled={isRefreshing}
          >
            <RefreshCw size={14} className={isRefreshing ? "spin-animation" : ""} />
            {isRefreshing ? 'Loading' : 'Refresh'}
          </button>

          {/* Generate Report Button */}
          <button 
            onClick={handleGenerateReport} 
            className="filter-select" 
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', border: '1px solid rgba(0, 242, 254, 0.4)', color: 'var(--accent-cyan)' }}
            disabled={isGeneratingReport}
          >
            <ShieldAlert size={14} className={isGeneratingReport ? "spin-animation" : ""} />
            {isGeneratingReport ? 'Generating...' : 'Generate Report'}
          </button>

          {/* Real-time pulse indicator */}
          <div className="live-indicator">
            <div className="pulse-dot"></div>
            <span>LIVE FEED</span>
          </div>
        </div>
      </header>

      {/* Main Grid Content */}
      <main className="dashboard-grid">
        {/* Statistics Panels */}
        <div className="soc-card stats-header-card">
          <div className="stat-icon-box">
            <Activity size={24} />
          </div>
          <div className="stat-info">
            <div className="stat-value">{stats.total_events}</div>
            <div className="stat-label">Total Events</div>
          </div>
        </div>

        <div className="soc-card stats-header-card">
          <div className="stat-icon-box" style={{ color: 'var(--accent-blue)', backgroundColor: 'rgba(59, 130, 246, 0.1)' }}>
            <Users size={24} />
          </div>
          <div className="stat-info">
            <div className="stat-value">{stats.unique_ips}</div>
            <div className="stat-label">Unique Attackers</div>
          </div>
        </div>

        <div className="soc-card stats-header-card">
          <div className="stat-icon-box" style={{ color: 'var(--accent-purple)', backgroundColor: 'rgba(168, 85, 247, 0.1)' }}>
            <Terminal size={24} />
          </div>
          <div className="stat-info">
            <div className="stat-value">{stats.ssh_events}</div>
            <div className="stat-label">SSH Attempts</div>
          </div>
        </div>

        <div className="soc-card stats-header-card">
          <div className="stat-icon-box" style={{ color: 'var(--accent-green)', backgroundColor: 'rgba(16, 185, 129, 0.1)' }}>
            <Globe size={24} />
          </div>
          <div className="stat-info">
            <div className="stat-value">{stats.http_events}</div>
            <div className="stat-label">HTTP Web Attacks</div>
          </div>
        </div>

        {/* Leaflet map of attack sources */}
        <div className="soc-card map-panel">
          <h2 className="card-title"><Globe size={18} /> Global Attack Map</h2>
          <div ref={mapContainerRef} className="map-container"></div>
        </div>

        {/* Live Attack Feed */}
        <div className="soc-card feed-panel">
          <h2 className="card-title"><ShieldAlert size={18} /> Live Attack Activity</h2>
          <div className="feed-list">
            {events.slice(0, 15).map(e => (
              <div key={e.id} className="feed-item" onClick={() => handleIpClick(e.source_ip)}>
                <div className="feed-item-header">
                  <span className="feed-ip">{e.source_ip}</span>
                  <span className="feed-time">
                    {new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </span>
                </div>
                <div className="feed-item-body">
                  <span className="feed-path">
                    {e.sensor_type === 'SSH' ? `login as: ${e.ssh_username}` : `${e.http_method} ${e.http_path}`}
                  </span>
                  <div>
                    <span className={`feed-badge ${e.sensor_type === 'SSH' ? 'badge-ssh' : 'badge-http'}`}>
                      {e.sensor_type}
                    </span>
                    {e.attack_type && e.attack_type !== 'scan' && (
                      <span className="feed-badge badge-attack">{e.attack_type}</span>
                    )}
                  </div>
                </div>
              </div>
            ))}
            {events.length === 0 && (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', marginTop: '2rem' }}>
                Waiting for incoming events...
              </div>
            )}
          </div>
        </div>

        {/* Attack Volume Timeline */}
        <div className="soc-card chart-panel">
          <h2 className="card-title"><TrendingUp size={18} /> Attack Volume Timeline (Last 24h)</h2>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={getTimelineData()}>
                <defs>
                  <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent-cyan)" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="var(--text-secondary)" fontSize={11} />
                <YAxis stroke="var(--text-secondary)" fontSize={11} />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--accent-cyan)' }}
                  labelStyle={{ color: 'var(--text-primary)' }}
                />
                <Area type="monotone" dataKey="Total" stroke="var(--accent-cyan)" fillOpacity={1} fill="url(#colorTotal)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Attack Composition by Sensor */}
        <div className="soc-card chart-panel">
          <h2 className="card-title"><Server size={18} /> Attack Composition Breakdown</h2>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={getTimelineData()}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="var(--text-secondary)" fontSize={11} />
                <YAxis stroke="var(--text-secondary)" fontSize={11} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--accent-blue)' }} />
                <Legend verticalAlign="top" height={36} />
                <Bar dataKey="SSH" stackId="a" fill="var(--accent-purple)" />
                <Bar dataKey="HTTP" stackId="a" fill="var(--accent-blue)" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Attacking IPs */}
        <div className="soc-card bottom-panel-3">
          <h2 className="card-title"><MapPin size={18} /> Top Attacking IPs</h2>
          <div className="panel-list">
            {topIps.map((ip, idx) => (
              <div key={ip.source_ip} className="list-row" onClick={() => handleIpClick(ip.source_ip)} style={{ cursor: 'pointer' }}>
                <span className="list-row-title">
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>#{idx+1}</span>
                  <span className="list-row-mono">{ip.source_ip}</span>
                </span>
                <span className="list-row-value">{ip.event_count} events</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Credentials */}
        <div className="soc-card bottom-panel-3">
          <h2 className="card-title"><Key size={18} /> Top Attempted Credentials</h2>
          <div className="panel-list">
            {topCredentials.map((cred, idx) => (
              <div key={idx} className="list-row">
                <span className="list-row-title">
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>#{idx+1}</span>
                  <span className="list-row-mono" style={{ color: 'var(--accent-purple)' }}>{cred.ssh_username}</span>
                  <span style={{ color: 'var(--text-muted)' }}>:</span>
                  <span className="list-row-mono">{cred.ssh_password}</span>
                </span>
                <span className="list-row-value" style={{ color: 'var(--accent-purple)' }}>{cred.attempts} attempts</span>
              </div>
            ))}
          </div>
        </div>

        {/* Campaigns Tracker */}
        <div className="soc-card bottom-panel-3">
          <h2 className="card-title"><AlertCircle size={18} /> Coordinated Campaigns</h2>
          <div className="panel-list">
            {campaigns.map(c => (
              <div key={c.id} className="list-row" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '0.25rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
                  <span className="list-row-title" style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--accent-cyan)' }}>
                    {c.name}
                  </span>
                  <span className="list-row-value" style={{ fontSize: '0.85rem' }}>
                    {c.ip_count} IPs
                  </span>
                </div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  Active: {new Date(c.last_active).toLocaleString()}
                </span>
              </div>
            ))}
            {campaigns.length === 0 && (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                No active campaigns detected yet.
              </div>
            )}
          </div>
        </div>

        {/* MITRE ATT&CK Heatmap Panel */}
        <div className="soc-card bottom-panel-3" style={{ gridColumn: 'span 8', height: '240px' }}>
          <h2 className="card-title"><Terminal size={18} /> MITRE ATT&CK Technique Alignment</h2>
          <div className="mitre-heatmap">
            {MITRE_TECHNIQUES.map(t => {
              const count = mitreCounts[t.id] || 0;
              return (
                <div key={t.id} className={`mitre-cell ${count > 0 ? 'mitre-cell-active' : ''}`}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="mitre-id">{t.id}</span>
                    {count > 0 && <span className="mitre-count">{count}</span>}
                  </div>
                  <div className="mitre-name">{t.name}</div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Sensor Health Monitoring */}
        <div className="soc-card bottom-panel-3" style={{ gridColumn: 'span 4', height: '240px' }}>
          <h2 className="card-title"><Server size={18} /> Honeypot Sensor Health</h2>
          <div className="panel-list">
            {sensorHealth.map(s => {
              const diffMs = new Date() - new Date(s.last_seen);
              const isHealthy = diffMs < 60000; // Active within 60s
              return (
                <div key={s.sensor_type} className="list-row" style={{ padding: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <div style={{
                      width: 10, height: 10, borderRadius: '50%',
                      backgroundColor: isHealthy ? 'var(--accent-green)' : '#f59e0b',
                      boxShadow: isHealthy ? '0 0 10px var(--accent-green)' : '0 0 10px #f59e0b'
                    }}></div>
                    <span style={{ fontWeight: 700 }}>{s.sensor_type} Sensor Node</span>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{s.event_count} Logs</div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      Last seen: {new Date(s.last_seen).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              );
            })}
            {sensorHealth.length === 0 && (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                Waiting for sensor registration...
              </div>
            )}
          </div>
        </div>
      </main>

      {/* IP Detail Drawer */}
      {selectedIp && (
        <>
          <div className="drawer-overlay" onClick={() => setSelectedIp(null)}></div>
          <div className="drawer-content">
            <div className="drawer-header">
              <div>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: 600 }}>
                  Attacker Profile
                </span>
                <h2 className="drawer-title-ip">{selectedIp}</h2>
              </div>
              <button className="drawer-close" onClick={() => setSelectedIp(null)}>
                <X size={24} />
              </button>
            </div>

            {detailLoading ? (
              <div style={{ color: 'var(--accent-cyan)', textAlign: 'center', padding: '3rem' }}>
                <RefreshCw size={24} className="spin-animation" style={{ margin: '0 auto 1rem' }} />
                Enriching threat intelligence...
              </div>
            ) : ipDetail ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                
                {/* Threat Intelligence Geolocation */}
                <div className="drawer-section">
                  <h3>Reputation & Location</h3>
                  <div className="profile-grid">
                    <div className="profile-field">
                      <span className="profile-field-label">Abuse Confidence</span>
                      <span className="profile-field-val">
                        <span className={`abuse-badge ${
                          (ipDetail.profile?.abuse_score || 0) > 50 ? 'badge-high' : 
                          (ipDetail.profile?.abuse_score || 0) > 10 ? 'badge-medium' : 'badge-low'
                        }`}>
                          {ipDetail.profile?.abuse_score || 0}%
                        </span>
                      </span>
                    </div>
                    <div className="profile-field">
                      <span className="profile-field-label">Report Count</span>
                      <span className="profile-field-val">{ipDetail.profile?.report_count || 0}</span>
                    </div>
                    <div className="profile-field">
                      <span className="profile-field-label">Country</span>
                      <span className="profile-field-val">{ipDetail.profile?.country || 'N/A'}</span>
                    </div>
                    <div className="profile-field">
                      <span className="profile-field-label">City</span>
                      <span className="profile-field-val">{ipDetail.profile?.city || 'N/A'}</span>
                    </div>
                  </div>
                </div>

                {/* ISP Network Details */}
                <div className="drawer-section">
                  <h3>Autonomous System (ASN)</h3>
                  <div className="profile-grid" style={{ gridTemplateColumns: '1fr' }}>
                    <div className="profile-field">
                      <span className="profile-field-label">ISP / Carrier</span>
                      <span className="profile-field-val">{ipDetail.profile?.isp || 'N/A'}</span>
                    </div>
                    <div className="profile-field">
                      <span className="profile-field-label">ASN / Group</span>
                      <span className="profile-field-val">{ipDetail.profile?.asn || 'N/A'}</span>
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK alignment observed */}
                <div className="drawer-section">
                  <h3>Observed MITRE Techniques</h3>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {ipDetail.mitre_techniques?.map(t => (
                      <span key={t.technique_id} className="feed-badge badge-ssh" style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.35rem 0.6rem' }}>
                        <b style={{ color: 'var(--accent-cyan)' }}>{t.technique_id}</b> {t.technique_name}
                      </span>
                    ))}
                    {(!ipDetail.mitre_techniques || ipDetail.mitre_techniques.length === 0) && (
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No specific techniques logged.</span>
                    )}
                  </div>
                </div>

                {/* Event Logs Timeline */}
                <div className="drawer-section" style={{ borderBottom: 'none' }}>
                  <h3>Event History (Last 200 Logs)</h3>
                  <div className="drawer-timeline-list">
                    {ipDetail.events?.map(ev => (
                      <div key={ev.id} className="timeline-card">
                        <div className="timeline-meta">
                          <span style={{ fontWeight: 600, color: ev.sensor_type === 'SSH' ? 'var(--accent-purple)' : 'var(--accent-blue)' }}>
                            {ev.sensor_type} ATTEMPT
                          </span>
                          <span>{new Date(ev.timestamp).toLocaleString()}</span>
                        </div>
                        <div className={`timeline-detail ${ev.sensor_type === 'SSH' ? 'timeline-detail-mono' : ''}`}>
                          {ev.sensor_type === 'SSH' 
                            ? `user: ${ev.ssh_username} | pass: ${ev.ssh_password}` 
                            : `${ev.http_method} ${ev.http_path}`}
                        </div>
                        {ev.attack_type && ev.attack_type !== 'scan' && (
                          <div style={{ marginTop: '0.25rem' }}>
                            <span className="feed-badge badge-attack" style={{ marginLeft: 0 }}>
                              {ev.attack_type}
                            </span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

              </div>
            ) : (
              <div style={{ color: 'var(--text-secondary)' }}>Unable to load IP data.</div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export default App;
