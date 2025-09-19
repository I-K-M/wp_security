
<h1>WP Security</h1>
<p><strong>WP Security</strong> is a Go-based toolkit designed to analyse and improve the security of WordPress websites.<br>
It combines a <strong>malware scanner</strong> and a <strong>surface attack scanner (pentest-style)</strong> to give developers and administrators a complete overview of their site’s security posture.</p>

<hr>

<h2>🚀 Features</h2>

<h3>🔍 Malware Scanner (<code>wp_malware_scan.go</code>)</h3>
<ul>
  <li>Scans WordPress files for suspicious code patterns.</li>
  <li>Detects usage of dangerous PHP functions (<code>base64_decode</code>, <code>eval</code>, <code>gzinflate</code>, etc.).</li>
  <li>Helps identify injected code and potentially compromised files.</li>
</ul>

<h3>🛡 Surface Attack Scanner (<code>wp_pentest.go</code>)</h3>
<ul>
  <li>Checks for sensitive files:
    <ul>
      <li><code>readme.html</code> (WordPress version disclosure)</li>
      <li><code>wp-config.php</code> (critical config exposure)</li>
      <li><code>.env</code> (credentials leak)</li>
      <li><code>.git/</code> (source code leak)</li>
    </ul>
  </li>
  <li>Tests API exposure:
    <ul>
      <li><code>/wp-json/wp/v2/users</code> (user enumeration)</li>
    </ul>
  </li>
  <li>Checks XML-RPC: <code>/xmlrpc.php</code> availability (often abused for brute force or DDoS).</li>
  <li>Detects directory listing in <code>/uploads/</code>.</li>
  <li>Analyses <strong>security headers</strong>:
    <ul>
      <li><code>Content-Security-Policy</code></li>
      <li><code>Strict-Transport-Security</code></li>
      <li><code>X-Frame-Options</code></li>
      <li><code>X-XSS-Protection</code></li>
    </ul>
  </li>
</ul>

<hr>

<h2>📂 Project structure</h2>
<pre><code>wp_security/
│── wp_malware_scan.go   # malware scanner
│── wp_pentest.go        # surface security scanner
│── README.md            # documentation
│── go.mod               # Go module definition (if used)
</code></pre>

<hr>

<h2>⚡ Installation</h2>
<ol>
  <li>Clone the repo:
    <pre><code>git clone https://github.com/I-K-M/wp_security.git
cd wp_security</code></pre>
  </li>
  <li>Build the binaries:
    <pre><code>go build wp_malware_scan.go
go build wp_pentest.go</code></pre>
  </li>
</ol>

<hr>

<h2>🖥 Usage</h2>

<h3>Malware scanner</h3>
<pre><code>./wp_malware_scan --path /var/www/html</code></pre>

<h3>Surface security scanner</h3>
<pre><code>./wp_pentest --url https://example.com</code></pre>

<hr>

<h2>📊 Example output (pentest)</h2>
<pre><code>=== WordPress Pentest Tool ===
Target: https://example.com

[-] readme.html not found
[-] REST API users protected
[+] xmlrpc.php exposed (Method Not Allowed, but endpoint accessible)
[-] wp-config.php protected
[-] .env not accessible
[-] .git directory protected
[-] uploads dir protected

=== Security Headers Check ===
[+] X-Frame-Options present
[+] Content-Security-Policy present
[-] X-XSS-Protection missing
[+] Strict-Transport-Security present
</code></pre>

<hr>

<h2>⚠️ Disclaimer</h2>
<p class="warning">This project is <strong>for educational and authorised testing only</strong>.</p>

<p>Valid use cases:</p>
<ul>
  <li>Scanning <strong>your own WordPress sites</strong></li>
  <li>Running in <strong>lab environments</strong> (e.g., DVWA, vulnerable WordPress Docker images)</li>
  <li>Conducting security reviews <strong>with explicit client authorisation</strong></li>
</ul>

<p class="warning">❌ Scanning third-party sites without permission is illegal.</p>
