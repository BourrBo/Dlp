import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";

export function LandingPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");

  function handleGetStarted(e: React.FormEvent) {
    e.preventDefault();
    navigate({ to: "/dashboard" });
  }

  function handleReviewDashboard() {
    navigate({ to: "/dashboard" });
  }

  return (
    <div className="landing-root">
      <main className="landing-hero">
        <div className="landing-badge">
          <span className="landing-badge-dot" aria-hidden="true" />
          <span>DATA LOSS PREVENTION</span>
        </div>

        <h1 className="landing-headline">
          <span className="landing-headline-navy">Your Data. Your Control.</span>
          <span className="landing-headline-purple">Your Security.</span>
        </h1>

        <p className="landing-subtitle">
          Protect sensitive information, detect exposed secrets,
          <br className="hidden sm:inline" /> and stay ahead of data security risks.
        </p>

        <form className="landing-cta" onSubmit={handleGetStarted}>
          <div className="landing-input-group">
            <input
              id="landing-email"
              type="email"
              placeholder="Enter your work email"
              className="landing-email-input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              aria-label="Work email address"
            />
            <button
              type="submit"
              id="landing-get-started-cta"
              className="landing-cta-btn"
            >
              Get Started
            </button>
          </div>
        </form>

        <div className="landing-demo-review">
          <button
            type="button"
            id="landing-review-dashboard-btn"
            onClick={handleReviewDashboard}
            className="landing-demo-btn"
          >
            <span>Review Live Dashboard</span>
            <span aria-hidden="true">&rarr;</span>
          </button>
        </div>
      </main>
    </div>
  );
}
