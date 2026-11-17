
const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// Keep your PubScale secret key in Render's
// environment variables. Never put it in GitHub.
const SECRET_KEY = process.env.PUBSCALE_SECRET_KEY;

app.get("/", (req, res) => {
  res.status(200).send("PubScale webhook server is running!");
});

app.get("/pubscale-webhook", (req, res) => {
  try {
    const { user_id, value, token, signature } = req.query;

    if (!SECRET_KEY) {
      console.error("Missing PUBSCALE_SECRET_KEY");
      return res.status(500).send("Server not configured");
    }

    if (!user_id || !value || !token || !signature) {
      return res.status(400).send("Missing callback parameters");
    }

    const amount = Number(value);

    if (!Number.isFinite(amount) || amount < 0) {
      return res.status(400).send("Invalid reward value");
    }

    // PubScale specifies integer conversion for value.
    const template =
      `${SECRET_KEY}.${user_id}.${Math.trunc(amount)}.${token}`;

    const expected = crypto
      .createHash("md5")
      .update(template)
      .digest("hex");

    const received = String(signature).toLowerCase();

    if (!/^[a-f0-9]{32}$/.test(received)) {
      return res.status(403).send("Invalid signature");
    }

    const valid = crypto.timingSafeEqual(
      Buffer.from(expected, "hex"),
      Buffer.from(received, "hex")
    );

    if (!valid) {
      return res.status(403).send("Signature verification failed");
    }

    console.log("Verified PubScale callback:", {
      user_id,
      value: amount,
      token
    });

    // TODO: Credit the user's balance in your database.
    // Store token with a UNIQUE constraint to prevent
    // duplicate rewards when PubScale retries callbacks.

    return res.status(200).send("Callback verified");
  } catch (error) {
    console.error(error);
    return res.status(500).send("Internal server error");
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
