from flask import Flask, render_template_string, jsonify
import pandas as pd
import os
import time

app = Flask(__name__)

LOG_FILE = 'traffic_log.csv'

ATTACK_LABELS = {
    0:  'Normal',
    1:  'Normal',
    -1: 'Unknown Anomaly',
    -2: 'DTLS Amplification',
    -3: 'TLS Heartbleed',
    -4: 'TLS POODLE',
    -5: 'DTLS Replay'
}

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>IoT IDS Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', sans-serif;
      background: #0d1117;
      color: #c9d1d9;
      min-height: 100vh;
    }
    header {
      background: #161b22;
      border-bottom: 1px solid #30363d;
      padding: 16px 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    header h1 { font-size: 1.3rem; color: #58a6ff; letter-spacing: 1px; }
    #status-badge {
      padding: 4px 14px;
      border-radius: 20px;
      font-size: 0.85rem;
      font-weight: 600;
      background: #238636;
      color: #fff;
    }
    #status-badge.alert { background: #da3633; }

    .stats-row {
      display: flex;
      gap: 16px;
      padding: 24px 32px 0;
      flex-wrap: wrap;
    }
    .stat-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 18px 24px;
      flex: 1;
      min-width: 160px;
    }
    .stat-card .label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
    .stat-card .value { font-size: 2rem; font-weight: 700; margin-top: 6px; }
    .stat-card.normal .value  { color: #3fb950; }
    .stat-card.anomaly .value { color: #f85149; }
    .stat-card.total .value   { color: #58a6ff; }
    .stat-card.rate .value    { color: #d29922; }

    .charts-row {
      display: flex;
      gap: 16px;
      padding: 20px 32px;
      flex-wrap: wrap;
    }
    .chart-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 20px;
      flex: 1;
      min-width: 300px;
    }
    .chart-card h3 { font-size: 0.9rem; color: #8b949e; margin-bottom: 14px; text-transform: uppercase; letter-spacing: 1px; }

    .table-section { padding: 0 32px 32px; }
    .table-section h3 { font-size: 0.9rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { background: #21262d; color: #8b949e; padding: 10px 14px; text-align: left; border-bottom: 1px solid #30363d; }
    td { padding: 9px 14px; border-bottom: 1px solid #21262d; }
    tr:hover td { background: #1c2128; }
    .badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 12px;
      font-size: 0.78rem;
      font-weight: 600;
    }
    .badge.normal  { background: #1a4429; color: #3fb950; }
    .badge.attack  { background: #3d1a1a; color: #f85149; }
    .badge.tls     { background: #1a2f4a; color: #58a6ff; }
    .badge.dtls    { background: #2a1f3d; color: #bc8cff; }

    #last-updated { padding: 0 32px 8px; font-size: 0.75rem; color: #484f58; }
  </style>
</head>
<body>
  <header>
    <h1>🛡 IoT Network Intrusion Detection System</h1>
    <span id="status-badge">● ALL CLEAR</span>
  </header>

  <div class="stats-row">
    <div class="stat-card total">
      <div class="label">Total Packets</div>
      <div class="value" id="stat-total">—</div>
    </div>
    <div class="stat-card normal">
      <div class="label">Normal Traffic</div>
      <div class="value" id="stat-normal">—</div>
    </div>
    <div class="stat-card anomaly">
      <div class="label">Anomalies</div>
      <div class="value" id="stat-anomaly">—</div>
    </div>
    <div class="stat-card rate">
      <div class="label">Attack Rate</div>
      <div class="value" id="stat-rate">—</div>
    </div>
  </div>

  <div class="charts-row">
    <div class="chart-card" style="max-width:340px">
      <h3>Traffic Distribution</h3>
      <canvas id="pieChart" height="220"></canvas>
    </div>
    <div class="chart-card">
      <h3>Packets Over Time</h3>
      <canvas id="lineChart" height="220"></canvas>
    </div>
    <div class="chart-card" style="max-width:320px">
      <h3>Attack Breakdown</h3>
      <canvas id="barChart" height="220"></canvas>
    </div>
  </div>

  <div id="last-updated">Last updated: —</div>

  <div class="table-section">
    <h3>Recent Packets (last 20)</h3>
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Protocol</th>
          <th>Payload (bytes)</th>
          <th>Proc. Time (ms)</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody id="packet-table"></tbody>
    </table>
  </div>

  <script>
    const ATTACK_NAMES = {
      '-1': 'Unknown Anomaly',
      '-2': 'DTLS Amplification',
      '-3': 'TLS Heartbleed',
      '-4': 'TLS POODLE',
      '-5': 'DTLS Replay'
    };
    const ATTACK_COLORS = ['#8b949e','#f85149','#d29922','#bc8cff','#58a6ff'];

    // Init charts
    const pieCtx = document.getElementById('pieChart').getContext('2d');
    const pieChart = new Chart(pieCtx, {
      type: 'doughnut',
      data: {
        labels: ['Normal', 'Anomaly'],
        datasets: [{ data: [0, 0], backgroundColor: ['#3fb950','#f85149'], borderWidth: 0 }]
      },
      options: { plugins: { legend: { labels: { color: '#c9d1d9' } } }, cutout: '65%' }
    });

    const lineCtx = document.getElementById('lineChart').getContext('2d');
    const lineChart = new Chart(lineCtx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          { label: 'Normal', data: [], borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.1)', tension: 0.3, fill: true },
          { label: 'Anomaly', data: [], borderColor: '#f85149', backgroundColor: 'rgba(248,81,73,0.1)', tension: 0.3, fill: true }
        ]
      },
      options: {
        plugins: { legend: { labels: { color: '#c9d1d9' } } },
        scales: {
          x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
          y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' }, beginAtZero: true }
        }
      }
    });

    const barCtx = document.getElementById('barChart').getContext('2d');
    const barChart = new Chart(barCtx, {
      type: 'bar',
      data: {
        labels: ['Unknown', 'DTLS Amp', 'TLS Heartbleed', 'TLS POODLE', 'DTLS Replay'],
        datasets: [{
          label: 'Count',
          data: [0, 0, 0, 0, 0],
          backgroundColor: ATTACK_COLORS,
          borderRadius: 4
        }]
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
          y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' }, beginAtZero: true }
        }
      }
    });

    function formatTime(ts) {
      const d = new Date(ts * 1000);
      return d.toLocaleTimeString();
    }

    async function refresh() {
      try {
        const res = await fetch('/api/data');
        const d = await res.json();

        // Stats
        document.getElementById('stat-total').textContent = d.total;
        document.getElementById('stat-normal').textContent = d.normal;
        document.getElementById('stat-anomaly').textContent = d.anomaly;
        document.getElementById('stat-rate').textContent = d.attack_rate + '%';
        document.getElementById('last-updated').textContent = 'Last updated: ' + new Date().toLocaleTimeString();

        // Status badge
        const badge = document.getElementById('status-badge');
        if (d.anomaly > 0) {
          badge.textContent = '⚠ THREATS DETECTED';
          badge.className = 'alert';
        } else {
          badge.textContent = '● ALL CLEAR';
          badge.className = '';
        }

        // Pie chart
        pieChart.data.datasets[0].data = [d.normal, d.anomaly];
        pieChart.update();

        // Bar chart
        barChart.data.datasets[0].data = [d.unknown, d.dtls_amp, d.heartbleed, d.poodle, d.replay];
        barChart.update();

        // Line chart (rolling 10 buckets)
        lineChart.data.labels = d.timeline.map(b => b.label);
        lineChart.data.datasets[0].data = d.timeline.map(b => b.normal);
        lineChart.data.datasets[1].data = d.timeline.map(b => b.anomaly);
        lineChart.update();

        // Table
        const tbody = document.getElementById('packet-table');
        tbody.innerHTML = '';
        d.recent.forEach(p => {
          const isAnomaly = p.score < 0;
          const attackName = isAnomaly ? (ATTACK_NAMES[String(p.score)] || 'Unknown') : 'Normal';
          const statusBadge = isAnomaly
            ? `<span class="badge attack">⚠ ${attackName}</span>`
            : `<span class="badge normal">✔ Normal</span>`;
          const protoBadge = p.protocol === 'TLS'
            ? `<span class="badge tls">TLS</span>`
            : `<span class="badge dtls">DTLS</span>`;
          tbody.innerHTML += `
            <tr>
              <td>${formatTime(p.timestamp)}</td>
              <td>${protoBadge}</td>
              <td>${p.payload_size}</td>
              <td>${parseFloat(p.proc_time).toFixed(3)}</td>
              <td>${statusBadge}</td>
            </tr>`;
        });
      } catch(e) {
        console.error('Refresh error:', e);
      }
    }

    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/data')
def api_data():
    if not os.path.exists(LOG_FILE):
        return jsonify({'error': 'No log file found'}), 404

    try:
        df = pd.read_csv(LOG_FILE)
        if df.empty:
            return jsonify({'total': 0, 'normal': 0, 'anomaly': 0, 'attack_rate': '0.0',
                            'unknown': 0, 'dtls_amp': 0, 'heartbleed': 0, 'poodle': 0, 'replay': 0,
                            'timeline': [], 'recent': []})

        # --- DATA SANITATION ---
        # Ensure critical columns are numeric, handle malformed/NaN data from manual edits
        df['anomaly_score'] = pd.to_numeric(df['anomaly_score'], errors='coerce')
        df['payload_size'] = pd.to_numeric(df['payload_size'], errors='coerce').fillna(0)
        df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce').fillna(time.time())
        df['processing_time_ms'] = pd.to_numeric(df['processing_time_ms'], errors='coerce').fillna(0)

        # --- COLUMN SHIFT RECOVERY ---
        # If anomaly_score is NaN but processing_time_ms looks like an attack code (-1 to -5), 
        # it means the 5-column server bug shifted the data. We fix it here.
        mask = df['anomaly_score'].isna() & df['processing_time_ms'].isin([-1, -2, -3, -4, -5])
        df.loc[mask, 'anomaly_score'] = df.loc[mask, 'processing_time_ms']
        
        # Finally fill remaining NaNs with 1 (Normal)
        df['anomaly_score'] = df['anomaly_score'].fillna(1)
        # -----------------------------

        df = df.sort_values('timestamp')

        total = len(df)
        anomaly_df = df[df['anomaly_score'] < 0]
        normal_count = total - len(anomaly_df)
        anomaly_count = len(anomaly_df)
        attack_rate = f"{anomaly_count / total * 100:.1f}" if total > 0 else "0.0"

        unknown    = int(len(df[df['anomaly_score'] == -1]))
        dtls_amp   = int(len(df[df['anomaly_score'] == -2]))
        heartbleed = int(len(df[df['anomaly_score'] == -3]))
        poodle     = int(len(df[df['anomaly_score'] == -4]))
        replay     = int(len(df[df['anomaly_score'] == -5]))

        # Timeline: bucket last 10 minutes into 10 x 1-min buckets
        now = df['timestamp'].max()
        start = now - 600
        buckets = []
        for i in range(10):
            b_start = start + i * 60
            b_end   = b_start + 60
            window  = df[(df['timestamp'] >= b_start) & (df['timestamp'] < b_end)]
            label_t = pd.to_datetime(b_start, unit='s').strftime('%H:%M')
            buckets.append({
                'label':   label_t,
                'normal':  int(len(window[window['anomaly_score'] >= 0])),
                'anomaly': int(len(window[window['anomaly_score'] < 0]))
            })

        # Recent 20 packets
        recent_rows = df.tail(20).iloc[::-1]
        recent = []
        for _, row in recent_rows.iterrows():
            recent.append({
                'timestamp':    row['timestamp'],
                'protocol':     row['protocol'],
                'payload_size': int(row['payload_size']),
                'proc_time':    row['processing_time_ms'],
                'score':        int(row['anomaly_score'])
            })

        return jsonify({
            'total':       total,
            'normal':      normal_count,
            'anomaly':     anomaly_count,
            'attack_rate': attack_rate,
            'unknown':     unknown,
            'dtls_amp':    dtls_amp,
            'heartbleed':  heartbleed,
            'poodle':      poodle,
            'replay':      replay,
            'timeline':    buckets,
            'recent':      recent
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting IoT IDS Dashboard on http://localhost:5050")
    app.run(host='localhost', port=5050, debug=False)
