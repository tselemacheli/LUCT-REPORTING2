// src/context/AuthContext.js
import React, { createContext, useState, useEffect } from 'react';
import axios from 'axios';
import { jwtDecode } from 'jwt-decode';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Use your Render deployment URL
  const API_BASE_URL = "https://luct-reporting2-13.onrender.com/api";

  // --------------------------
  // Initialize user from token
  // --------------------------
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const decoded = jwtDecode(token);
        if (decoded.exp * 1000 > Date.now()) {
          setUser({ role: decoded.role, id: decoded.id });
          localStorage.setItem('userId', decoded.id);
          axios.defaults.headers.common['Authorization'] = Bearer ${token};
        } else {
          logout();
        }
      } catch (err) {
        console.error('Token decoding error:', err);
        logout();
      }
    }
    setLoading(false);
  }, []);

  // --------------------------
  // Login function
  // --------------------------
  const login = async (identifier, password) => {
    try {
      setLoading(true);
      const res = await axios.post(${API_BASE_URL}/login, { identifier, password });
      localStorage.setItem('token', res.data.token);
      const decoded = jwtDecode(res.data.token);
      localStorage.setItem('userId', decoded.id);
      axios.defaults.headers.common['Authorization'] = Bearer ${res.data.token};
      setUser({ role: res.data.role, id: decoded.id });
      return res.data;
    } catch (err) {
      console.error('Login error:', err);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  // --------------------------
  // Logout function
  // --------------------------
  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('userId');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
  };

  // --------------------------
  // API helpers
  // --------------------------
  const api = {
    // USERS
    register: (data) => axios.post(${API_BASE_URL}/register, data),
    login, // already defined above

    // COURSES
    getCourses: (search = '') => axios.get(${API_BASE_URL}/courses, { params: { search } }),
    addCourse: (data) => axios.post(${API_BASE_URL}/courses, data),

    // CLASSES
    getClasses: (search = '') => axios.get(${API_BASE_URL}/classes, { params: { search } }),
    addClass: (data) => axios.post(${API_BASE_URL}/classes, data),
    getClassDetails: (id) => axios.get(${API_BASE_URL}/class/${id}),

    // ENROLLMENTS
    enrollClass: (classId) => axios.post(${API_BASE_URL}/enroll, { classId }),
    myEnrollments: (search = '') => axios.get(${API_BASE_URL}/my-enrollments, { params: { search } }),
    availableClasses: (search = '') => axios.get(${API_BASE_URL}/available-classes, { params: { search } }),

    // REPORTS
    submitReport: (data) => axios.post(${API_BASE_URL}/reports, data),
    getReports: (search = '') => axios.get(${API_BASE_URL}/reports, { params: { search } }),
    addFeedback: (id, feedback) => axios.put(${API_BASE_URL}/reports/${id}/feedback, { feedback }),
    getReportAttendance: (id) => axios.get(${API_BASE_URL}/reports/${id}/attendance),
    getReportRatings: (id) => axios.get(${API_BASE_URL}/reports/${id}/ratings),
    exportReports: () => axios.get(${API_BASE_URL}/reports/export, { responseType: 'blob' }),

    // ATTENDANCE
    markAttendance: (data) => axios.post(${API_BASE_URL}/attendance, data),
    myAttendance: (search = '') => axios.get(${API_BASE_URL}/my-attendance, { params: { search } }),

    // RATINGS
    rateReport: (data) => axios.post(${API_BASE_URL}/ratings, data),
    rateLecturer: (data) => axios.post(${API_BASE_URL}/lecturer-ratings, data),
    getLecturerRatings: (lecturerId) => axios.get(${API_BASE_URL}/lecturer-ratings/${lecturerId}),
    getAllLecturerRatings: (search = '') => axios.get(${API_BASE_URL}/lecturer-ratings, { params: { search } }),

    // LECTURERS
    getLecturers: () => axios.get(${API_BASE_URL}/lecturers),
    myLecturers: () => axios.get(${API_BASE_URL}/my-lecturers),
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, api }}>
      {children}
    </AuthContext.Provider>
  );
};
