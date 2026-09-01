import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { adoptCookieToken } from "./api";
import "./styles.css";

// If the Authentik callback just redirected here, its session cookie is the
// source of the token — pick it up before the app decides auth state.
adoptCookieToken();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
