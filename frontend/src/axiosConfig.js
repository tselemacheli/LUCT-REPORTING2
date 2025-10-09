// src/api/api.js
import axios from "axios";

// Base URL: use environment variable for production, fallback to Render URL
const API_BASE_URL =
  process.env.REACT_APP_API_URL || "https://luct-reporting2-13.onrender.com/api";

// Create Axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000, // 15 seconds timeout for slow backend responses
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor to attach JWT token automatically
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle 401 globally and return only data
api.interceptors.response.use(
  (response) => response.data, // Simplify usage: returns only response.data
  (error) => {
    if (error.response?.status === 401) {
      console.warn("Unauthorized. Logging out...");
      localStorage.removeItem("token");
      localStorage.removeItem("userId");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

export default api;
