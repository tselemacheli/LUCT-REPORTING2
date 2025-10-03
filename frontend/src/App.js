import React, { useContext } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, AuthContext } from './AuthContext';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import Footer from './components/Footer';
import './App.css';

const AppContent = () => {
  const { user, apiStatus } = useContext(AuthContext);

  return (
    <div className="App">
      <Router>
        <div className="app-content">
          <Routes>
            <Route 
              path="/login" 
              element={!user ? <Login /> : <Navigate to="/dashboard" />} 
            />
            <Route 
              path="/register" 
              element={!user ? <Register /> : <Navigate to="/dashboard" />} 
            />
            <Route 
              path="/dashboard" 
              element={user ? <Dashboard /> : <Navigate to="/login" />} 
            />
            <Route 
              path="/" 
              element={<Navigate to={user ? "/dashboard" : "/login"} />} 
            />
            <Route 
              path="*" 
              element={<Navigate to="/" />} 
            />
          </Routes>
        </div>
        <Footer />
      </Router>

      {/* API Status Indicator */}
      {apiStatus === 'unhealthy' && (
        <div className="api-status-banner">
          <div className="container">
            <i className="fas fa-exclamation-triangle me-2"></i>
            Unable to connect to server. Please check your connection.
          </div>
        </div>
      )}
    </div>
  );
};

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
