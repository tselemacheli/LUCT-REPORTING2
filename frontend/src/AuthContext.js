import React, { createContext, useState, useEffect } from 'react';
import api, { checkApiHealth } from './axiosConfig';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [apiStatus, setApiStatus] = useState('checking');

  useEffect(() => {
    checkApiStatus();
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');

    if (token && userData) {
      try {
        const parsedUser = JSON.parse(userData);
        setUser(parsedUser);
        
        // Verify token is still valid
        api.get('/api/courses')
          .catch(() => {
            // Token is invalid, logout
            logout();
          });
      } catch (error) {
        console.error('Error parsing user data:', error);
        logout();
      }
    }
    
    setLoading(false);
  }, []);

  const checkApiStatus = async () => {
    const health = await checkApiHealth();
    setApiStatus(health.status);
  };

  const login = async (identifier, password) => {
    try {
      setLoading(true);
      const response = await api.post('/api/login', { identifier, password });
      
      const { token, role, user: userInfo } = response.data;
      
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(userInfo));
      localStorage.setItem('userRole', role);
      
      setUser(userInfo);
      setApiStatus('healthy');
      
      return response.data;
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('userRole');
    setUser(null);
    window.location.href = '/login';
  };

  const value = {
    user,
    login,
    logout,
    loading,
    apiStatus,
    checkApiStatus
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
