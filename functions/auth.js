export async function onRequest(context) {
    const { request, env } = context;
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

    try {
        const data = await request.json();
        const { action, user_id, password, name, role, twoFactorEnabled, twoFactorSecret, status } = data;

        if (action === "register") {
            const existing = await env.DB.prepare("SELECT user_id FROM users WHERE user_id = ?").bind(user_id).first();
            if (existing) return Response.json({ success: false, message: "User ID already exists" });

            const secret = twoFactorSecret || "NLCPSECRET" + Date.now();
            await env.DB.prepare(
                "INSERT INTO users (name, user_id, password, role, twoFactorEnabled, twoFactorSecret, status) VALUES (?, ?, ?, ?, ?, ?, ?)"
            ).bind(name, user_id, password, role, 0, secret, "offline").run();

            const newUser = await env.DB.prepare("SELECT * FROM users WHERE user_id = ?").bind(user_id).first();
            return Response.json({ success: true, message: "User registered securely", user: newUser });
        }

        if (action === "login") {
            const user = await env.DB.prepare("SELECT * FROM users WHERE user_id = ? AND password = ?").bind(user_id, password).first();
            if (!user) return Response.json({ success: false, message: "Invalid ID or password" });
            return Response.json({ success: true, user });
        }

        if (action === "get_users") {
            const { results } = await env.DB.prepare("SELECT name, user_id, role, status, twoFactorEnabled, password, twoFactorSecret FROM users").all();
            return Response.json({ success: true, users: results });
        }

        if (action === "delete_user") {
            await env.DB.prepare("DELETE FROM users WHERE user_id = ?").bind(user_id).run();
            return Response.json({ success: true, message: "Account deleted securely" });
        }

        if (action === "update_user") {
            await env.DB.prepare(
                "UPDATE users SET password = ?, twoFactorEnabled = ?, twoFactorSecret = ?, name = ? WHERE user_id = ?"
            ).bind(password, twoFactorEnabled ? 1 : 0, twoFactorSecret, name, user_id).run();
            return Response.json({ success: true, message: "User updated" });
        }

        if (action === "update_status") {
            await env.DB.prepare("UPDATE users SET status = ? WHERE user_id = ?").bind(status, user_id).run();
            return Response.json({ success: true, message: "Status updated" });
        }

        return Response.json({ success: false, message: "Unknown API action" });
    } catch (err) {
        return Response.json({ success: false, message: err.message }, { status: 500 });
    }
}
