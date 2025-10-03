import axios from 'axios';

// API base URL configuration
const getApiBaseUrl = () => {
  // Use environment variable if set
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  
  // If running on Vercel production
  if (window.location.hostname === 'luct-reporting.vercel.app') {
    return 'https://luct-reporting2-2.onrender.com';
  }
  
  // If running on Vercel preview
  if (window.location.hostname.includes('.vercel.app')) {
    return 'https://luct-reporting2-2.onrender.com';
  }
  
  // Default to local development
  return 'http://localhost:5000';
};

const API_BASE_URL = getApiBaseUrl();
console.log('🚀 API Base URL:', API_BASE_URL);

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
    
    console.log(`🔄 API Call: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('❌ API Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    console.log(`✅ API Success: ${response.status} ${response.config.url}`);
    return response;
  },
  (error) => {
    console.error('❌ API Response Error:', {
      url: error.config?.url,
      status: error.response?.status,
      message: error.response?.data?.message || error.message
    });

    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      localStorage.removeItem('userRole');
      
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
    }
    
    return Promise.reject(error);
  }
);

export const checkApiHealth = async () => {
  try {
    const response = await api.get('/health');
    return { 
      healthy: true, 
      data: response.data,
      url: API_BASE_URL
    };
  } catch (error) {
    return { 
      healthy: false, 
      error: error.message,
      status: error.response?.status,
      url: API_BASE_URL
    };
  }
};

export default api;
