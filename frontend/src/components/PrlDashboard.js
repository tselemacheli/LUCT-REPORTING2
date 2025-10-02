import React, { useState, useEffect } from 'react';
import api from '../axiosConfig';
import '../App.css';

const PrlDashboard = () => {
  const [state, setState] = useState({
    reports: [],
    courses: [],
    classes: [],
    lecturerRatings: [],
    feedback: {},
    error: '',
    success: '',
    activeTab: 'courses',
    expandedItems: {
      courses: {},
      reports: {},
      classes: {},
      ratings: {}
    }
  });

  const [loading, setLoading] = useState({
    reports: false,
    courses: false,
    classes: false,
    ratings: false,
    feedback: false
  });

  useEffect(() => {
    fetchAllData();
  }, []); // Removed search dependency

  const setStateField = (field, value) => {
    setState(prev => ({ ...prev, [field]: value }));
  };

  const setLoadingField = (field, value) => {
    setLoading(prev => ({ ...prev, [field]: value }));
  };

  const showMessage = (type, message, duration = 5000) => {
    setStateField(type, message);
    setTimeout(() => setStateField(type, ''), duration);
  };

  const toggleTab = (tabName) => {
    setStateField('activeTab', tabName);
  };

  const toggleExpand = (section, itemId) => {
    setStateField('expandedItems', {
      ...state.expandedItems,
      [section]: {
        ...state.expandedItems[section],
        [itemId]: !state.expandedItems[section][itemId]
      }
    });
  };

  const fetchAllData = async () => {
    await Promise.all([
      fetchReports(),
      fetchCourses(),
      fetchClasses(),
      fetchLecturerRatings()
    ]);
  };

  const fetchReports = async () => {
    setLoadingField('reports', true);
    try {
      const res = await api.get('/reports'); // Removed search parameter
      setStateField('reports', res.data || []);
    } catch (err) {
      showMessage('error', 'Error fetching reports: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('reports', false);
    }
  };

  const fetchCourses = async () => {
    setLoadingField('courses', true);
    try {
      const res = await api.get('/courses'); // Removed search parameter
      setStateField('courses', res.data || []);
    } catch (err) {
      showMessage('error', 'Error fetching courses: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('courses', false);
    }
  };

  const fetchClasses = async () => {
    setLoadingField('classes', true);
    try {
      const res = await api.get('/classes'); // Removed search parameter
      setStateField('classes', res.data || []);
    } catch (err) {
      showMessage('error', 'Error fetching classes: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('classes', false);
    }
  };

  const fetchLecturerRatings = async () => {
    setLoadingField('ratings', true);
    try {
      const res = await api.get('/lecturer-ratings'); // Removed search parameter
      setStateField('lecturerRatings', res.data || []);
    } catch (err) {
      showMessage('error', 'Error fetching lecturer ratings: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('ratings', false);
    }
  };

  const handleFeedbackChange = (reportId, value) => {
    setStateField('feedback', {
      ...state.feedback,
      [reportId]: value
    });
  };

  const submitFeedback = async (reportId) => {
    const feedbackText = state.feedback[reportId]?.trim();
    
    if (!feedbackText) {
      showMessage('error', 'Please provide feedback before submitting');
      return;
    }

    setLoadingField('feedback', true);
    try {
      await api.put(`/reports/${reportId}/feedback`, { 
        feedback: feedbackText 
      });
      
      showMessage('success', 'Feedback submitted successfully');
      
      setStateField('feedback', {
        ...state.feedback,
        [reportId]: ''
      });
      
      fetchReports();
    } catch (err) {
      showMessage('error', 'Error submitting feedback: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('feedback', false);
    }
  };

  const getAttendancePercentage = (actual, total) => {
    if (!total) return '0%';
    return `${Math.round((actual / total) * 100)}%`;
  };

  const getStatusBadge = (attendancePercentage) => {
    const percentage = parseInt(attendancePercentage);
    if (percentage >= 80) return { label: 'Excellent', type: 'success' };
    if (percentage >= 60) return { label: 'Good', type: 'warning' };
    return { label: 'Needs Attention', type: 'danger' };
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'No date';
    try {
      const date = new Date(dateString);
      return isNaN(date.getTime()) ? 'No date' : date.toLocaleDateString();
    } catch {
      return 'No date';
    }
  };

  const { reports, courses, classes, lecturerRatings, feedback, error, success, activeTab, expandedItems } = state;

  // Pagination states
  const [pagination, setPagination] = useState({
    courses: 0,
    reports: 0,
    classes: 0,
    ratings: 0
  });

  const itemsPerPage = 4;

  const getPaginatedItems = (items, type) => {
    const startIndex = pagination[type] * itemsPerPage;
    return items.slice(startIndex, startIndex + itemsPerPage);
  };

  const nextPage = (type) => {
    setPagination(prev => ({
      ...prev,
      [type]: prev[type] + 1
    }));
  };

  const prevPage = (type) => {
    setPagination(prev => ({
      ...prev,
      [type]: Math.max(0, prev[type] - 1)
    }));
  };

  const canNext = (items, type) => {
    return (pagination[type] + 1) * itemsPerPage < items.length;
  };

  const canPrev = (type) => {
    return pagination[type] > 0;
  };

  return (
    <div className="prl-dashboard">
      {error && <div className="col-12"><div className="auth-error">{error}</div></div>}
      {success && <div className="col-12"><div className="auth-success">{success}</div></div>}

      {/* Tab Navigation */}
      <div className="tab-navigation">
        <div className="tab-buttons">
          <button 
            className={`tab-button ${activeTab === 'courses' ? 'active' : ''}`}
            onClick={() => toggleTab('courses')}
          >
            <i className="fas fa-book me-2"></i>
            Courses ({courses.length})
          </button>
          <button 
            className={`tab-button ${activeTab === 'reports' ? 'active' : ''}`}
            onClick={() => toggleTab('reports')}
          >
            <i className="fas fa-comment-dots me-2"></i>
            Reports ({reports.length})
          </button>
          <button 
            className={`tab-button ${activeTab === 'classes' ? 'active' : ''}`}
            onClick={() => toggleTab('classes')}
          >
            <i className="fas fa-users me-2"></i>
            Classes ({classes.length})
          </button>
          <button 
            className={`tab-button ${activeTab === 'ratings' ? 'active' : ''}`}
            onClick={() => toggleTab('ratings')}
          >
            <i className="fas fa-star me-2"></i>
            Ratings ({lecturerRatings.length})
          </button>
        </div>
      </div>

      {/* Courses Tab */}
      {activeTab === 'courses' && (
        <div className="tab-content">
          {loading.courses ? (
            <div className="loading">
              <div className="loading-spinner"></div>
              <p className="mt-2">Loading courses...</p>
            </div>
          ) : courses.length > 0 ? (
            <div className="cards-grid">
              {getPaginatedItems(courses, 'courses').map((course) => (
                <div key={course.id} className="info-card">
                  <div className="card-header">
                    <h4>{course.name}</h4>
                    <span className="status-badge active">Active</span>
                  </div>
                  <div className="card-content">
                    <div className="info-row">
                      <i className="fas fa-code"></i>
                      <span>Code: {course.code}</span>
                    </div>
                    <div className="info-row">
                      <i className="fas fa-building"></i>
                      <span>Faculty: {course.faculty_name}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <i className="fas fa-book fa-3x mb-3"></i>
              <h3>No Courses Found</h3>
              <p>No courses are currently available.</p>
            </div>
          )}
          
          {/* Pagination */}
          {courses.length > itemsPerPage && (
            <div className="pagination">
              <button 
                className="btn btn-outline"
                onClick={() => prevPage('courses')}
                disabled={!canPrev('courses')}
              >
                <i className="fas fa-chevron-left"></i> Previous
              </button>
              <span className="page-info">
                Page {pagination.courses + 1} of {Math.ceil(courses.length / itemsPerPage)}
              </span>
              <button 
                className="btn btn-outline"
                onClick={() => nextPage('courses')}
                disabled={!canNext(courses, 'courses')}
              >
                Next <i className="fas fa-chevron-right"></i>
              </button>
            </div>
          )}
        </div>
      )}

      {/* Reports Tab */}
      {activeTab === 'reports' && (
        <div className="tab-content">
          {loading.reports ? (
            <div className="loading">
              <div className="loading-spinner"></div>
              <p className="mt-2">Loading reports...</p>
            </div>
          ) : reports.length > 0 ? (
            <div className="cards-grid">
              {getPaginatedItems(reports, 'reports').map((report) => {
                const attendancePercentage = getAttendancePercentage(report.actual_present, report.total_registered);
                const status = getStatusBadge(attendancePercentage);
                
                return (
                  <div key={report.id} className="info-card">
                    <div className="card-header">
                      <h4>{report.course_name} - {report.class_name}</h4>
                      <span className={`status-badge ${status.type}`}>
                        {status.label}
                      </span>
                    </div>
                    <div className="card-content">
                      <div className="info-row">
                        <i className="fas fa-calendar"></i>
                        <span>Date: {formatDate(report.date_lecture)}</span>
                      </div>
                      <div className="info-row">
                        <i className="fas fa-users"></i>
                        <span>Attendance: {report.actual_present}/{report.total_registered} ({attendancePercentage})</span>
                      </div>
                      <div className="info-row">
                        <i className="fas fa-calendar-week"></i>
                        <span>Week: {report.week}</span>
                      </div>
                      
                      {expandedItems.reports[report.id] && (
                        <div className="expanded-content">
                          <div className="feedback-section">
                            <label className="section-label">Your Feedback:</label>
                            <textarea
                              placeholder="Provide constructive feedback for this report..."
                              value={feedback[report.id] || ''}
                              onChange={(e) => handleFeedbackChange(report.id, e.target.value)}
                              className="feedback-input"
                              rows="3"
                              disabled={loading.feedback}
                            />
                          </div>

                          <button
                            onClick={() => submitFeedback(report.id)}
                            className="btn btn-warning w-100 mt-2"
                            disabled={loading.feedback || !feedback[report.id]?.trim()}
                          >
                            {loading.feedback ? (
                              <>
                                <div className="loading-spinner"></div>
                                Submitting...
                              </>
                            ) : (
                              <>
                                <i className="fas fa-paper-plane me-1"></i>
                                Submit Feedback
                              </>
                            )}
                          </button>

                          {report.prl_feedback && (
                            <div className="previous-feedback mt-3">
                              <label className="section-label">Previous Feedback:</label>
                              <div className="feedback-text">
                                {report.prl_feedback}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                    <div className="card-footer">
                      <div className="card-actions">
                        <button 
                          className="btn btn-primary"
                          onClick={() => toggleExpand('reports', report.id)}
                        >
                          {expandedItems.reports[report.id] ? (
                            <>
                              <i className="fas fa-times me-1"></i>
                              Hide Feedback
                            </>
                          ) : (
                            <>
                              <i className="fas fa-comment me-1"></i>
                              Provide Feedback
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="empty-state">
              <i className="fas fa-file-alt fa-3x mb-3"></i>
              <h3>No Reports Available</h3>
              <p>No reports are currently available for feedback.</p>
            </div>
          )}
          
          {/* Pagination */}
          {reports.length > itemsPerPage && (
            <div className="pagination">
              <button 
                className="btn btn-outline"
                onClick={() => prevPage('reports')}
                disabled={!canPrev('reports')}
              >
                <i className="fas fa-chevron-left"></i> Previous
              </button>
              <span className="page-info">
                Page {pagination.reports + 1} of {Math.ceil(reports.length / itemsPerPage)}
              </span>
              <button 
                className="btn btn-outline"
                onClick={() => nextPage('reports')}
                disabled={!canNext(reports, 'reports')}
              >
                Next <i className="fas fa-chevron-right"></i>
              </button>
            </div>
          )}
        </div>
      )}

      {/* Classes Tab - Updated with Cards Layout */}
      {activeTab === 'classes' && (
        <div className="tab-content">
          {loading.classes ? (
            <div className="loading">
              <div className="loading-spinner"></div>
              <p className="mt-2">Loading classes...</p>
            </div>
          ) : classes.length > 0 ? (
            <div className="cards-grid">
              {getPaginatedItems(classes, 'classes').map((classItem) => (
                <div key={classItem.id} className="info-card">
                  <div className="card-header">
                    <h4>{classItem.name}</h4>
                    <span className={`status-badge ${classItem.lecturer_name ? 'assigned' : 'unassigned'}`}>
                      {classItem.lecturer_name ? 'Assigned' : 'Unassigned'}
                    </span>
                  </div>
                  <div className="card-content">
                    <div className="info-row">
                      <i className="fas fa-book"></i>
                      <span><strong>Course:</strong> {classItem.course_name || 'Not assigned'}</span>
                    </div>
                    <div className="info-row">
                      <i className="fas fa-chalkboard-teacher"></i>
                      <span><strong>Lecturer:</strong> {classItem.lecturer_name || 'Unassigned'}</span>
                    </div>
                    <div className="info-row">
                      <i className="fas fa-user-graduate"></i>
                      <span><strong>Students:</strong> {classItem.total_students || 0}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <i className="fas fa-users fa-3x mb-3"></i>
              <h3>No Classes Found</h3>
              <p>No classes are currently available.</p>
            </div>
          )}
          
          {/* Pagination */}
          {classes.length > itemsPerPage && (
            <div className="pagination">
              <button 
                className="btn btn-outline"
                onClick={() => prevPage('classes')}
                disabled={!canPrev('classes')}
              >
                <i className="fas fa-chevron-left"></i> Previous
              </button>
              <span className="page-info">
                Page {pagination.classes + 1} of {Math.ceil(classes.length / itemsPerPage)}
              </span>
              <button 
                className="btn btn-outline"
                onClick={() => nextPage('classes')}
                disabled={!canNext(classes, 'classes')}
              >
                Next <i className="fas fa-chevron-right"></i>
              </button>
            </div>
          )}
        </div>
      )}

      {/* Ratings Tab */}
      {activeTab === 'ratings' && (
        <div className="tab-content">
          {loading.ratings ? (
            <div className="loading">
              <div className="loading-spinner"></div>
              <p className="mt-2">Loading ratings...</p>
            </div>
          ) : lecturerRatings.length > 0 ? (
            <div className="cards-grid">
              {getPaginatedItems(lecturerRatings, 'ratings').map((rating) => (
                <div key={rating.id} className="info-card">
                  <div className="card-header">
                    <h4>{rating.lecturer_name}</h4>
                    <div className="rating-display">
                      <div className="stars">
                        {'★'.repeat(rating.rating)}{'☆'.repeat(5 - rating.rating)}
                      </div>
                    </div>
                  </div>
                  <div className="card-content">
                    <div className="info-row">
                      <i className="fas fa-user-graduate"></i>
                      <span>Rated by: {rating.student_name}</span>
                    </div>
                    <div className="info-row">
                      <i className="fas fa-star"></i>
                      <span>Rating: {rating.rating}/5</span>
                    </div>
                    
                    {rating.comment && (
                      <div className="info-row full-width">
                        <i className="fas fa-comment"></i>
                        <div>
                          <div className="comment-label">Comment:</div>
                          <div className="comment-text">{rating.comment}</div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <i className="fas fa-star fa-3x mb-3"></i>
              <h3>No Ratings Available</h3>
              <p>No lecturer ratings have been submitted yet.</p>
            </div>
          )}
          
          {/* Pagination */}
          {lecturerRatings.length > itemsPerPage && (
            <div className="pagination">
              <button 
                className="btn btn-outline"
                onClick={() => prevPage('ratings')}
                disabled={!canPrev('ratings')}
              >
                <i className="fas fa-chevron-left"></i> Previous
              </button>
              <span className="page-info">
                Page {pagination.ratings + 1} of {Math.ceil(lecturerRatings.length / itemsPerPage)}
              </span>
              <button 
                className="btn btn-outline"
                onClick={() => nextPage('ratings')}
                disabled={!canNext(lecturerRatings, 'ratings')}
              >
                Next <i className="fas fa-chevron-right"></i>
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default PrlDashboard;