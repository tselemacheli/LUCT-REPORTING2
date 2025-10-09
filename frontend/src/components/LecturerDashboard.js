import React, { useState, useEffect, useCallback } from 'react';
import api from '../api/api';
import * as XLSX from 'xlsx';
import '../App.css';

const LecturerDashboard = () => {
  const [classes, setClasses] = useState([]);
  const [selectedClass, setSelectedClass] = useState(null);
  const [reports, setReports] = useState([]);
  const [lecturerRatings, setLecturerRatings] = useState([]);
  const [attendances, setAttendances] = useState([]);
  const [search, setSearch] = useState('');
  const [expandedReports, setExpandedReports] = useState({});
  const [form, setForm] = useState({
    week: '',
    dateLecture: '',
    venue: '',
    scheduledTime: '',
    topic: '',
    learningOutcomes: '',
    recommendations: ''
  });
  const [loading, setLoading] = useState({
    classes: false,
    reports: false,
    ratings: false,
    submit: false
  });
  const [error, setError] = useState('');

  // Debounced search
  useEffect(() => {
    const delayDebounce = setTimeout(() => {
      fetchClasses();
      fetchReports();
    }, 500);
    return () => clearTimeout(delayDebounce);
  }, [search]);

  // Initial ratings fetch
  useEffect(() => {
    fetchLecturerRatings();
  }, []);

  // API fetch functions
  const fetchClasses = async () => {
    setLoading(prev => ({ ...prev, classes: true }));
    try {
      const res = await api.get(`/classes?search=${encodeURIComponent(search)}`);
      setClasses(res.data || []);
      setError('');
    } catch (err) {
      setError('Error fetching classes: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoading(prev => ({ ...prev, classes: false }));
    }
  };

  const fetchReports = async () => {
    setLoading(prev => ({ ...prev, reports: true }));
    try {
      const res = await api.get(`/reports?search=${encodeURIComponent(search)}`);
      setReports(res.data || []);
      setError('');
    } catch (err) {
      setError('Error fetching reports: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoading(prev => ({ ...prev, reports: false }));
    }
  };

  const fetchLecturerRatings = async () => {
    setLoading(prev => ({ ...prev, ratings: true }));
    try {
      const userId = localStorage.getItem('userId');
      const res = await api.get(`/lecturer-ratings/${userId}`);
      setLecturerRatings(res.data || []);
      setError('');
    } catch (err) {
      setError('Error fetching lecturer ratings: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoading(prev => ({ ...prev, ratings: false }));
    }
  };

  const loadClass = async (id) => {
    try {
      const res = await api.get(`/class/${id}`);
      setSelectedClass(res.data);
      setAttendances(res.data.students.map(s => ({ studentId: s.id, present: true })));
      setError('');
    } catch (err) {
      setError('Error loading class: ' + (err.response?.data?.message || err.message));
    }
  };

  const toggleAttendance = (studentId) => {
    setAttendances(prev =>
      prev.map(a => (a.studentId === studentId ? { ...a, present: !a.present } : a))
    );
  };

  const submitReport = async () => {
    if (!selectedClass) return;
    setLoading(prev => ({ ...prev, submit: true }));
    try {
      await api.post('/reports', { ...form, classId: selectedClass.id, attendances });
      alert('Report submitted successfully!');
      fetchReports();
      setForm({
        week: '',
        dateLecture: '',
        venue: '',
        scheduledTime: '',
        topic: '',
        learningOutcomes: '',
        recommendations: ''
      });
      setSelectedClass(null);
      setAttendances([]);
      setError('');
    } catch (err) {
      setError('Error submitting report: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoading(prev => ({ ...prev, submit: false }));
    }
  };

  const toggleReportDetails = (id) => {
    setExpandedReports(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const downloadRatingsAsXLSX = () => {
    if (!lecturerRatings.length) return alert('No ratings data available');
    const data = lecturerRatings.map(r => ({
      'Student ID': r.studentId,
      'Rating': r.rating,
      'Comment': r.comment || 'No comment',
      'Date': new Date(r.createdAt).toLocaleDateString()
    }));
    const ws = XLSX.utils.json_to_sheet(data);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Lecturer Ratings');
    XLSX.writeFile(wb, 'lecturer-ratings.xlsx');
  };

  return (
    <div className="lecturer-dashboard">
      {error && <div className="auth-error">{error}</div>}

      <div className="dashboard-column">
        {/* Classes */}
        <div className="dashboard-card">
          <div className="dashboard-card-header">
            <i className="fas fa-chalkboard-teacher me-2"></i>My Classes
          </div>
          <div className="dashboard-card-body">
            <input
              type="text"
              placeholder="Search classes..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="dashboard-input mb-3"
            />
            {loading.classes ? (
              <p className="text-center text-muted">Loading classes...</p>
            ) : classes.length ? classes.map(cls => (
              <div key={cls.id} className="dashboard-subcard">
                <h6>{cls.name}</h6>
                <p className="text-muted">{cls.course_name}</p>
                <button onClick={() => loadClass(cls.id)} className="dashboard-button primary">
                  Create Report
                </button>
              </div>
            )) : (
              <div className="text-center text-muted py-4">
                <i className="fas fa-chalkboard-teacher fa-2x mb-2"></i>
                <p>No classes found</p>
              </div>
            )}
          </div>
        </div>

        {/* Reports */}
        <div className="dashboard-card">
          <div className="dashboard-card-header">
            <i className="fas fa-file-alt me-2"></i>My Reports
          </div>
          <div className="dashboard-card-body">
            {loading.reports ? (
              <p className="text-center text-muted">Loading reports...</p>
            ) : reports.length ? reports.map(report => (
              <div key={report.id} className="dashboard-subcard">
                <div className="d-flex justify-content-between align-items-center">
                  <div>
                    <h6>{report.class_name}</h6>
                    <small className="text-muted">Week {report.week}</small>
                  </div>
                  <button onClick={() => toggleReportDetails(report.id)} className="dashboard-button success">
                    {expandedReports[report.id] ? 'Hide' : 'View'}
                  </button>
                </div>
                {expandedReports[report.id] && (
                  <div className="report-details mt-3">
                    <p><strong>Topic:</strong> {report.topic}</p>
                    <p><strong>Venue:</strong> {report.venue}</p>
                    <p><strong>Learning Outcomes:</strong> {report.learning_outcomes}</p>
                    <p><strong>Recommendations:</strong> {report.recommendations}</p>
                    <p><strong>Attendance:</strong> {report.attendance_count} students</p>
                  </div>
                )}
              </div>
            )) : (
              <div className="text-center text-muted py-4">
                <i className="fas fa-file-alt fa-2x mb-2"></i>
                <p>No reports submitted yet</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Report Form & Ratings */}
      <div className="dashboard-column">
        {selectedClass && (
          <div className="dashboard-card">
            <div className="dashboard-card-header">
              <i className="fas fa-edit me-2"></i>Create Report for {selectedClass.name}
            </div>
            <div className="dashboard-card-body">
              <form>
                {Object.keys(form).map(field => (
                  <input
                    key={field}
                    type={field === 'dateLecture' ? 'date' : 'text'}
                    placeholder={field.replace(/([A-Z])/g, ' $1').toLowerCase()}
                    value={form[field]}
                    onChange={e => setForm(prev => ({ ...prev, [field]: e.target.value }))}
                    className="dashboard-input"
                  />
                ))}

                <h6 className="mt-4 mb-3">Attendance</h6>
                {attendances.map(a => {
                  const student = selectedClass.students.find(s => s.id === a.studentId);
                  return (
                    <div key={a.studentId} className="attendance-row">
                      <span className="flex-grow-1">{student?.name}</span>
                      <button
                        type="button"
                        onClick={() => toggleAttendance(a.studentId)}
                        className={`dashboard-button ${a.present ? 'success' : 'danger'}`}
                      >
                        {a.present ? 'Present' : 'Absent'}
                      </button>
                    </div>
                  );
                })}

                <button
                  type="button"
                  onClick={submitReport}
                  className="dashboard-button primary w-100 mt-4"
                  disabled={loading.submit}
                >
                  {loading.submit ? 'Submitting...' : 'Submit Report'}
                </button>
              </form>
            </div>
          </div>
        )}

        <div className="dashboard-card">
          <div className="dashboard-card-header">
            <i className="fas fa-star me-2"></i>My Ratings
            <button
              onClick={downloadRatingsAsXLSX}
              className="dashboard-button success float-end"
              disabled={loading.ratings || !lecturerRatings.length}
            >
              <i className="fas fa-download me-1"></i>Export
            </button>
          </div>
          <div className="dashboard-card-body">
            {loading.ratings ? (
              <p className="text-center text-muted">Loading ratings...</p>
            ) : lecturerRatings.length ? lecturerRatings.map(r => (
              <div key={r.id} className="dashboard-subcard">
                <div className="d-flex justify-content-between align-items-start">
                  <div>
                    <h6>Rating: {r.rating}/5</h6>
                    <p className="mb-1">{r.comment || 'No comment provided'}</p>
                    <small className="text-muted">Student ID: {r.studentId}</small>
                  </div>
                  <div className="text-warning">
                    {'★'.repeat(r.rating)}{'☆'.repeat(5 - r.rating)}
                  </div>
                </div>
              </div>
            )) : (
              <div className="text-center text-muted py-4">
                <i className="fas fa-star fa-2x mb-2"></i>
                <p>No ratings received yet</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default LecturerDashboard;
