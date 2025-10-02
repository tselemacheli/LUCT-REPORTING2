import React, { useState, useContext } from 'react';
import { AuthContext } from '../AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import api from '../axiosConfig';
import '../App.css';

const Register = () => {
  const [formData, setFormData] = useState({
    name: '',
    password: '',
    identifier: '',
    role: 'student'
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const navigate = useNavigate();

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const validateInputs = () => {
    const { name, password, identifier, role } = formData;

    // Name validation
    if (!/^[a-zA-Z ]+$/.test(name) || name.trim().split(/\s+/).length > 3) {
      setError('Invalid name: maximum 3 words, letters and spaces only');
      return false;
    }

    // Password validation
    if (!/^\d+$/.test(password)) {
      setError('Invalid password: numbers only');
      return false;
    }

    // Identifier validation
    if (!identifier) {
      setError('Identifier is required');
      return false;
    }

    if (role === 'student' && !/^\d+$/.test(identifier)) {
      setError('Invalid student identifier: numbers only');
      return false;
    }

    if (['lecturer', 'pl', 'prl'].includes(role) && !/^[A-Za-z0-9]+$/.test(identifier)) {
      setError('Invalid identifier: alphanumeric characters only for lecturers and staff');
      return false;
    }

    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!validateInputs()) return;

    setLoading(true);
    
    try {
      await api.post('/register', formData);
      
      // Show success message and redirect
      alert('Registration successful! Please log in with your credentials.');
      navigate('/login');
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed. Please try again.');
      console.error('Registration error:', err);
    } finally {
      setLoading(false);
    }
  };

  const getRoleDescription = (role) => {
    const descriptions = {
      student: 'Students use numeric identifiers',
      lecturer: 'Lecturers use alphanumeric identifiers',
      pl: 'Program Leaders use alphanumeric identifiers',
      prl: 'Principal Lecturers use alphanumeric identifiers'
    };
    return descriptions[role] || '';
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h2>Create Account</h2>
          <p className="mb-0">Join our platform today</p>
        </div>
        
        <div className="auth-body">
          <form onSubmit={handleSubmit}>
            <div className="mb-3">
              <input
                type="text"
                value={formData.name}
                onChange={(e) => handleInputChange('name', e.target.value)}
                placeholder="Full Name (max 3 words, letters only)"
                className="auth-input"
                required
                disabled={loading}
              />
            </div>

            <div className="mb-3">
              <input
                type="password"
                value={formData.password}
                onChange={(e) => handleInputChange('password', e.target.value)}
                placeholder="Password (numbers only)"
                className="auth-input"
                required
                disabled={loading}
              />
            </div>

            <div className="mb-3">
              <input
                type="text"
                value={formData.identifier}
                onChange={(e) => handleInputChange('identifier', e.target.value)}
                placeholder="Identifier"
                className="auth-input"
                required
                disabled={loading}
              />
              <small className="text-muted">
                {getRoleDescription(formData.role)}
              </small>
            </div>

            <div className="mb-4">
              <select
                value={formData.role}
                onChange={(e) => handleInputChange('role', e.target.value)}
                className="auth-input"
                required
                disabled={loading}
              >
                <option value="student">Student</option>
                <option value="lecturer">Lecturer</option>
                <option value="pl">Program Leader</option>
                <option value="prl">Principal Lecturer</option>
              </select>
            </div>

            <button
              type="submit"
              className="auth-button"
              disabled={loading}
            >
              {loading ? (
                <>
                  <div className="loading-spinner"></div>
                  Creating Account...
                </>
              ) : (
                'Create Account'
              )}
            </button>
          </form>

          {error && (
            <div className="auth-error">
              {error}
            </div>
          )}

          <div className="auth-link">
            <p>
              Already have an account?{' '}
              <Link to="/login">Sign in here</Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;