export async function onRequest(context) {
    const { request, env } = context;
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

    try {
        const data = await request.json();
        const { action, email, password, name, role, twoFactorEnabled, twoFactorSecret, status } = data;

        if (action === "register") {
            const existing = await env.DB.prepare("SELECT email FROM users WHERE email = ?").bind(email).first();
            if (existing) return Response.json({ success: false, message: "Email already exists in database" });

            const secret = twoFactorSecret || "NLCPSECRET" + Date.now();
            await env.DB.prepare(
                "INSERT INTO users (name, email, password, role, twoFactorEnabled, twoFactorSecret, status) VALUES (?, ?, ?, ?, ?, ?, ?)"
            ).bind(name, email, password, role, 0, secret, "offline").run();

            const newUser = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
            return Response.json({ success: true, message: "User registered securely", user: newUser });
        }

        if (action === "login") {
            const user = await env.DB.prepare("SELECT * FROM users WHERE email = ? AND password = ?").bind(email, password).first();
            if (!user) return Response.json({ success: false, message: "Invalid credentials" });
            return Response.json({ success: true, user });
        }

        if (action === "get_users") {
            const { results } = await env.DB.prepare("SELECT name, email, role, status, twoFactorEnabled, password, twoFactorSecret FROM users").all();
            return Response.json({ success: true, users: results });
        }

        if (action === "delete_user") {
            await env.DB.prepare("DELETE FROM users WHERE email = ?").bind(email).run();
            return Response.json({ success: true, message: "Account deleted securely" });
        }

        if (action === "update_user") {
            await env.DB.prepare(
                "UPDATE users SET password = ?, twoFactorEnabled = ?, twoFactorSecret = ?, name = ? WHERE email = ?"
            ).bind(password, twoFactorEnabled ? 1 : 0, twoFactorSecret, name, email).run();
            return Response.json({ success: true, message: "User updated" });
        }

        if (action === "update_status") {
            await env.DB.prepare("UPDATE users SET status = ? WHERE email = ?").bind(status, email).run();
            return Response.json({ success: true, message: "Status updated" });
        }

        return Response.json({ success: false, message: "Unknown API action" });
    } catch (err) {
        return Response.json({ success: false, message: err.message }, { status: 500 });
    }
}