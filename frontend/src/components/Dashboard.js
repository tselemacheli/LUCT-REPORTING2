import React, { useContext } from 'react';
import { AuthContext } from '../AuthContext';
import StudentDashboard from './StudentDashboard';
import LecturerDashboard from './LecturerDashboard';
import PrlDashboard from './PrlDashboard';
import PlDashboard from './PlDashboard';
import '../App.css';

const Dashboard = () => {
  const { user, logout, loading } = useContext(AuthContext);

  if (loading) {
    return (
      <div className="loading">
        <div className="loading-spinner"></div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="container">
        <div className="card">
          <div className="card-body text-center">
            <h3 className="text-danger">Authentication Error</h3>
            <p>No user logged in. Please log in again.</p>
            <button onClick={() => window.location.href = '/login'} className="btn btn-primary">
              Go to Login
            </button>
          </div>
        </div>
      </div>
    );
  }

  const renderDashboard = () => {
    const roleComponents = {
      student: StudentDashboard,
      lecturer: LecturerDashboard,
      prl: PrlDashboard,
      pl: PlDashboard
    };

    const DashboardComponent = roleComponents[user.role];
    return DashboardComponent ? <DashboardComponent /> : <InvalidRole />;
  };

  const InvalidRole = () => (
    <div className="card">
      <div className="card-body text-center">
        <h3 className="text-danger">Invalid Role</h3>
        <p>Your role "{user.role}" is not recognized.</p>
      </div>
    </div>
  );

  const getRoleDisplayName = (role) => {
    const roleNames = {
      student: 'Student',
      lecturer: 'Lecturer',
      prl: 'Principal Lecturer',
      pl: 'Program Leader'
    };
    return roleNames[role] || role;
  };

  return (
    <div className="container">
      <div className="dashboard-header">
        <div>
          <h1 className="dashboard-title">
            {getRoleDisplayName(user.role)} Dashboard
          </h1>
          
        </div>
        <button 
          onClick={logout} 
          className="btn btn-danger"
          aria-label="Logout"
        >
          <i className="fas fa-sign-out-alt"></i> Logout
        </button>
      </div>
      
      {renderDashboard()}
    </div>
  );
};

export default Dashboard;