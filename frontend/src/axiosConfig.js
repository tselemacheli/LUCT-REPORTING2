import axios from 'axios';

// API base URL configuration
const getApiBaseUrl = () => {
  // Use environment variable if set
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  
  // If running on Vercel
  if (window.location.hostname.includes('vercel.app')) {
    return 'https://luct-reporting2-2.onrender.com';
  }
  
  // Default to local development
  return 'http://localhost:5000';
};

const API_BASE_URL = getApiBaseUrl();

console.log('API Base URL:', API_BASE_URL);

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      localStorage.removeItem('userRole');
      window.location.href = '/login';
    }
    
    return Promise.reject(error);
  }
);

export const checkApiHealth = async () => {
  try {
    const response = await api.get('/health');
    return { healthy: true, data: response.data };
  } catch (error) {
    return { 
      healthy: false, 
      error: error.message,
      status: error.response?.status 
    };
  }
};

export default api;
