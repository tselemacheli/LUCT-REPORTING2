import React, { createContext, useState, useEffect } from 'react';
import axios from 'axios';
import { jwtDecode } from 'jwt-decode';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const decoded = jwtDecode(token);
        if (decoded.exp * 1000 > Date.now()) {
          setUser({ role: decoded.role, id: decoded.id });
          localStorage.setItem('userId', decoded.id); // Store userId for lecturer ratings
          axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        } else {
          localStorage.removeItem('token');
          localStorage.removeItem('userId');
          delete axios.defaults.headers.common['Authorization'];
          setUser(null);
        }
      } catch (err) {
        localStorage.removeItem('token');
        localStorage.removeItem('userId');
        delete axios.defaults.headers.common['Authorization'];
        setUser(null);
      }
    }
    setLoading(false);
  }, []);

  const login = async (identifier, password) => {
    try {
      setLoading(true);
      const res = await axios.post('http://localhost:5000/api/login', { identifier, password });
      localStorage.setItem('token', res.data.token);
      localStorage.setItem('userId', jwtDecode(res.data.token).id); // Store userId
      axios.defaults.headers.common['Authorization'] = `Bearer ${res.data.token}`;
      setUser({ role: res.data.role, id: jwtDecode(res.data.token).id });
    } catch (err) {
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('userId');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};