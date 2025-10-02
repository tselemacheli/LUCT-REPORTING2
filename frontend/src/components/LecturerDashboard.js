import React, { useState, useEffect } from 'react';
import api from '../axiosConfig';
import * as XLSX from 'xlsx';
import '../App.css';

const LecturerDashboard = () => {
  const [state, setState] = useState({
    classes: [],
    selectedClass: null,
    reports: [],
    lecturerRatings: [],
    search: '',
    expandedReports: {},
    error: ''
  });

  const [form, setForm] = useState({
    week: '',
    dateLecture: '',
    venue: '',
    scheduledTime: '',
    topic: '',
    learningOutcomes: '',
    recommendations: ''
  });

  const [attendances, setAttendances] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchClasses();
    fetchReports();
    fetchLecturerRatings();
  }, [state.search]);

  const setStateField = (field, value) => {
    setState(prev => ({ ...prev, [field]: value }));
  };

  const setFormField = (field, value) => {
    setForm(prev => ({ ...prev, [field]: value }));
  };

  const fetchClasses = async () => {
    try {
      const res = await api.get(`/classes?search=${encodeURIComponent(state.search)}`);
      setStateField('classes', res.data || []);
    } catch (err) {
      setStateField('error', 'Error fetching classes: ' + (err.response?.data?.message || err.message));
    }
  };

  const fetchReports = async () => {
    try {
      const res = await api.get(`/reports?search=${encodeURIComponent(state.search)}`);
      setStateField('reports', res.data || []);
    } catch (err) {
      setStateField('error', 'Error fetching reports: ' + (err.response?.data?.message || err.message));
    }
  };

  const fetchLecturerRatings = async () => {
    try {
      const res = await api.get(`/lecturer-ratings/${localStorage.getItem('userId')}`);
      setStateField('lecturerRatings', res.data || []);
    } catch (err) {
      setStateField('error', 'Error fetching lecturer ratings: ' + (err.response?.data?.message || err.message));
    }
  };

  const loadClass = async (id) => {
    try {
      const res = await api.get(`/class/${id}`);
      setStateField('selectedClass', res.data);
      setAttendances(res.data.students.map(student => ({
        studentId: student.id,
        present: true
      })));
    } catch (err) {
      setStateField('error', 'Error loading class: ' + (err.response?.data?.message || err.message));
    }
  };

  const toggleAttendance = (studentId) => {
    setAttendances(prev =>
      prev.map(attendance =>
        attendance.studentId === studentId
          ? { ...attendance, present: !attendance.present }
          : attendance
      )
    );
  };

  const submitReport = async () => {
    if (!state.selectedClass) return;

    setLoading(true);
    try {
      await api.post('/reports', {
        ...form,
        classId: state.selectedClass.id,
        attendances
      });

      alert('Report submitted successfully!');
      fetchReports();
      
      // Reset form
      setForm({
        week: '',
        dateLecture: '',
        venue: '',
        scheduledTime: '',
        topic: '',
        learningOutcomes: '',
        recommendations: ''
      });
      setStateField('selectedClass', null);
      setAttendances([]);
    } catch (err) {
      setStateField('error', 'Error submitting report: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoading(false);
    }
  };

  const toggleReportDetails = (id) => {
    setStateField('expandedReports', {
      ...state.expandedReports,
      [id]: !state.expandedReports[id]
    });
  };

  const downloadRatingsAsXLSX = () => {
    if (state.lecturerRatings.length === 0) {
      alert('No ratings data available to download.');
      return;
    }

    const ratingsData = state.lecturerRatings.map(rating => ({
      'Student ID': rating.studentId,
      'Rating': rating.rating,
      'Comment': rating.comment || 'No comment',
      'Date': new Date(rating.createdAt).toLocaleDateString()
    }));

    const worksheet = XLSX.utils.json_to_sheet(ratingsData);
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Lecturer Ratings');
    XLSX.writeFile(workbook, 'lecturer-ratings.xlsx');
  };

  const { classes, selectedClass, reports, lecturerRatings, search, expandedReports, error } = state;

  return (
    <div className="lecturer-dashboard">
      {error && <div className="col-12"><div className="auth-error">{error}</div></div>}

      {/* Classes and Reports Section */}
      <div className="dashboard-column">
        {/* Classes Card */}
        <div className="dashboard-card">
          <div className="dashboard-card-header">
            <i className="fas fa-chalkboard-teacher me-2"></i>
            My Classes
          </div>
          <div className="dashboard-card-body">
            <input
              type="text"
              placeholder="Search classes..."
              value={search}
              onChange={(e) => setStateField('search', e.target.value)}
              className="dashboard-input"
            />
            
            {classes.length > 0 ? (
              classes.map((cls) => (
                <div key={cls.id} className="dashboard-subcard">
                  <h6>{cls.name}</h6>
                  <p className="mb-2 text-muted">{cls.course_name}</p>
                  <button
                    onClick={() => loadClass(cls.id)}
                    className="dashboard-button primary"
                  >
                    Create Report
                  </button>
                </div>
              ))
            ) : (
              <div className="text-center text-muted py-4">
                <i className="fas fa-chalkboard-teacher fa-2x mb-2"></i>
                <p>No classes found</p>
              </div>
            )}
          </div>
        </div>

        {/* Reports Card */}
        <div className="dashboard-card">
          <div className="dashboard-card-header">
            <i className="fas fa-file-alt me-2"></i>
            My Reports
          </div>
          <div className="dashboard-card-body">
            {reports.length > 0 ? (
              reports.map((report) => (
                <div key={report.id} className="dashboard-subcard">
                  <div className="d-flex justify-content-between align-items-center">
                    <div>
                      <h6>{report.class_name}</h6>
                      <small className="text-muted">Week {report.week}</small>
                    </div>
                    <button
                      onClick={() => toggleReportDetails(report.id)}
                      className="dashboard-button success"
                    >
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
              ))
            ) : (
              <div className="text-center text-muted py-4">
                <i className="fas fa-file-alt fa-2x mb-2"></i>
                <p>No reports submitted yet</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Report Form and Ratings Section */}
      <div className="dashboard-column">
        {/* Report Form Card */}
        {selectedClass && (
          <div className="dashboard-card">
            <div className="dashboard-card-header">
              <i className="fas fa-edit me-2"></i>
              Create Report for {selectedClass.name}
            </div>
            <div className="dashboard-card-body">
              <form>
                {Object.keys(form).map((field) => (
                  <input
                    key={field}
                    type={field === 'dateLecture' ? 'date' : 'text'}
                    placeholder={field.replace(/([A-Z])/g, ' $1').toLowerCase()}
                    value={form[field]}
                    onChange={(e) => setFormField(field, e.target.value)}
                    className="dashboard-input"
                  />
                ))}

                <h6 className="mt-4 mb-3">Attendance</h6>
                {attendances.map((attendance) => {
                  const student = selectedClass.students.find(s => s.id === attendance.studentId);
                  return (
                    <div key={attendance.studentId} className="attendance-row">
                      <span className="flex-grow-1">{student?.name}</span>
                      <button
                        type="button"
                        onClick={() => toggleAttendance(attendance.studentId)}
                        className={`dashboard-button ${attendance.present ? 'success' : 'danger'}`}
                      >
                        {attendance.present ? 'Present' : 'Absent'}
                      </button>
                    </div>
                  );
                })}

                <button
                  type="button"
                  onClick={submitReport}
                  className="dashboard-button primary w-100 mt-4"
                  disabled={loading}
                >
                  {loading ? 'Submitting...' : 'Submit Report'}
                </button>
              </form>
            </div>
          </div>
        )}

        {/* Ratings Card */}
        <div className="dashboard-card">
          <div className="dashboard-card-header">
            <i className="fas fa-star me-2"></i>
            My Ratings
            <button
              onClick={downloadRatingsAsXLSX}
              className="dashboard-button success float-end"
              disabled={lecturerRatings.length === 0}
            >
              <i className="fas fa-download me-1"></i>
              Export
            </button>
          </div>
          <div className="dashboard-card-body">
            {lecturerRatings.length > 0 ? (
              lecturerRatings.map((rating) => (
                <div key={rating.id} className="dashboard-subcard">
                  <div className="d-flex justify-content-between align-items-start">
                    <div>
                      <h6>Rating: {rating.rating}/5</h6>
                      <p className="mb-1">{rating.comment || 'No comment provided'}</p>
                      <small className="text-muted">
                        Student ID: {rating.studentId}
                      </small>
                    </div>
                    <div className="text-warning">
                      {'★'.repeat(rating.rating)}{'☆'.repeat(5 - rating.rating)}
                    </div>
                  </div>
                </div>
              ))
            ) : (
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