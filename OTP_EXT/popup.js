<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>TOTP</title>
  <style>
    body {
      font-family: sans-serif;
      width: 240px;
      padding: 12px;
    }
    form {
      display: flex;
      flex-direction: column;
      margin-bottom: 12px;
    }
    form input {
      margin: 4px 0;
      padding: 6px;
      font-size: 0.9em;
    }
    form button {
      padding: 6px;
      font-size: 0.9em;
      cursor: pointer;
    }
    #otp-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .otp-entry {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 6px;
      border: 1px solid #ddd;
      border-radius: 4px;
    }
    .otp-label {
      font-weight: bold;
      margin-right: 8px;
      flex: 1;
    }
    .otp-code {
      font-family: monospace;
      cursor: pointer;
      user-select: all;
    }
    .copy-feedback {
      color: green;
      font-size: 0.8em;
      margin-left: 6px;
    }
    #countdown {
      margin-top: 12px;
      font-size: 0.8em;
      color: #666;
      text-align: center;
    }
  </style>
</head>
<body>
  <form id="add-form">
    <input type="text" id="label-input" placeholder="Label (e.g. Gmail)" required>
    <input type="text" id="secret-input" placeholder="Base32 Secret" required>
    <button type="submit">Add OTP</button>
  </form>

  <div id="otp-list">
    <!-- dynamically filled -->
  </div>

  <div id="countdown">--s until refresh</div>

  <script src="popup.js"></script>
</body>
</html>
