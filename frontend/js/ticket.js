
document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("create-ticket-form");

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        // 1️⃣ Get token from localStorage (saved by Dev 2)
        const token = localStorage.getItem("access_token");

        if (!token) {
            alert("You are not logged in. Please login first.");
            return;
        }

        // 2️⃣ Collect form data
        const ticketData = {
            title: document.getElementById("title").value.trim(),
            category: document.getElementById("category").value,
            description: document.getElementById("description").value.trim()
        };

        // 3️⃣ Basic validation
        if (!ticketData.title || !ticketData.category || !ticketData.description) {
            alert("Please fill in all fields.");
            return;
        }

        try {
            // 4️⃣ Call backend API (POST /tickets/)
            const response = await fetch("http://localhost:8000/tickets/", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + token
                },
                body: JSON.stringify(ticketData)
            });

            // 5️⃣ Handle response
            if (response.ok) {
                alert("Ticket created successfully!");
                form.reset(); // clear form
            } else {
                const errorData = await response.json();
                alert("Error: " + (errorData.detail || "Failed to create ticket"));
            }

        } catch (error) {
            console.error("Network error:", error);
            alert("Backend server is not running.");
        }
    });
});
