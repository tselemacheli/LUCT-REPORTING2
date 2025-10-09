import React, { useState, useEffect } from 'react';
import api from '../axiosConfig';
import '../App.css';

const StudentDashboard = () => {
  const [state, setState] = useState({
    classes: [],
    enrollments: [],
    lecturers: [],
    classId: '',
    lecturerRatings: {},
    error: '',
    success: ''
  });

  const [loading, setLoading] = useState({
    classes: false,
    enrollments: false,
    lecturers: false
  });

  useEffect(() => {
    fetchAvailableClasses();
    fetchEnrollments();
    fetchLecturers();
  }, []);

  const setStateField = (field, value) => setState(prev => ({ ...prev, [field]: value }));
  const setLoadingField = (field, value) => setLoading(prev => ({ ...prev, [field]: value }));

  const showMessage = (type, message, duration = 3000) => {
    setStateField(type, message);
    setTimeout(() => setStateField(type, ''), duration);
  };

  const fetchAvailableClasses = async () => {
    setLoadingField('classes', true);
    try {
      const res = await api.get('/available-classes');
      setStateField('classes', res.data || []);
    } catch (err) {
      showMessage('error', 'Error fetching classes: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('classes', false);
    }
  };

  const fetchEnrollments = async () => {
    setLoadingField('enrollments', true);
    try {
      const res = await api.get('/my-enrollments');
      setStateField('enrollments', res.data || []);
    } catch (err) {
      showMessage('error', 'Error fetching enrollments: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('enrollments', false);
    }
  };

  const fetchLecturers = async () => {
    setLoadingField('lecturers', true);
    try {
      const res = await api.get('/my-lecturers');
      setStateField('lecturers', res.data || []);
    } catch (err) {
      showMessage('error', 'Error fetching lecturers: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('lecturers', false);
    }
  };

  const handleEnroll = async () => {
    if (!state.classId) {
      showMessage('error', 'Please select a class to enroll');
      return;
    }
    setLoadingField('enrollments', true);
    try {
      await api.post('/enroll', { classId: state.classId });
      showMessage('success', 'Enrolled successfully');
      setStateField('classId', '');
      fetchAvailableClasses();
      fetchEnrollments();
      fetchLecturers();
    } catch (err) {
      showMessage('error', 'Error enrolling: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('enrollments', false);
    }
  };

  const handleLecturerRatingChange = (lecturerId, field, value) => {
    setStateField('lecturerRatings', {
      ...state.lecturerRatings,
      [lecturerId]: {
        ...state.lecturerRatings[lecturerId],
        [field]: value
      }
    });
  };

  const submitLecturerRating = async (lecturerId) => {
    const { rating, comment } = state.lecturerRatings[lecturerId] || {};
    if (!rating || rating < 1 || rating > 5) {
      showMessage('error', 'Rating must be between 1 and 5');
      return;
    }
    setLoadingField('lecturers', true);
    try {
      await api.post('/lecturer-ratings', {
        lecturerId,
        rating: Number(rating),
        comment: comment || ''
      });
      showMessage('success', 'Lecturer rating submitted');
      handleLecturerRatingChange(lecturerId, 'rating', '');
      handleLecturerRatingChange(lecturerId, 'comment', '');
    } catch (err) {
      showMessage('error', 'Error submitting lecturer rating: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('lecturers', false);
    }
  };

  const { classes, enrollments, lecturers, classId, lecturerRatings, error, success } = state;

  return (
    <div className="dashboard-grid">
      {error && <div className="col-12"><div className="auth-error">{error}</div></div>}
      {success && <div className="col-12"><div className="auth-success">{success}</div></div>}

      {/* Enrollment Section */}
      <div className="card">
        <div className="card-header">
          <i className="fas fa-book-open me-2"></i>
          Class Enrollment
        </div>
        <div className="card-body dashboard-section">
          <div className="mb-4">
            <h6 className="text-primary mb-3">Enroll in a New Class</h6>
            {loading.classes ? (
              <div className="loading"><div className="loading-spinner"></div></div>
            ) : (
              <>
                <select
                  value={classId}
                  onChange={(e) => setStateField('classId', e.target.value)}
                  className="form-control mb-3"
                  disabled={loading.enrollments}
                >
                  <option value="">Select Class</option>
                  {classes.map(cl => (
                    <option key={cl.id} value={cl.id}>{cl.name} - {cl.course_name}</option>
                  ))}
                </select>
                <button
                  onClick={handleEnroll}
                  className="btn btn-primary w-100"
                  disabled={loading.enrollments || !classId}
                >
                  {loading.enrollments ? 'Enrolling...' : 'Enroll in Class'}
                </button>
              </>
            )}
          </div>

          <div>
            <h6 className="text-primary mb-3">Your Enrolled Classes</h6>
            {loading.enrollments ? (
              <div className="loading"><div className="loading-spinner"></div></div>
            ) : enrollments.length > 0 ? (
              enrollments.map(enrollment => (
                <div key={enrollment.id} className="card mb-2 border-primary">
                  <div className="card-body py-2">
                    <h6 className="mb-1">{enrollment.name}</h6>
                    <small className="text-muted">{enrollment.course_name}</small>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center text-muted py-3">
                <i className="fas fa-inbox fa-2x mb-2"></i>
                <p>No enrolled classes found</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Lecturer Rating Section */}
      <div className="card">
        <div className="card-header">
          <i className="fas fa-star me-2"></i>
          Rate Your Lecturers
        </div>
        <div className="card-body dashboard-section">
          {loading.lecturers ? (
            <div className="loading"><div className="loading-spinner"></div></div>
          ) : lecturers.length > 0 ? (
            lecturers.map(lecturer => (
              <div key={lecturer.id} className="card mb-3 border-warning">
                <div className="card-body">
                  <h6 className="text-warning mb-3">Rate {lecturer.name}</h6>
                  <div className="row g-2 align-items-center">
                    <div className="col-md-3">
                      <input
                        type="number"
                        min="1"
                        max="5"
                        value={lecturerRatings[lecturer.id]?.rating || ''}
                        onChange={(e) => handleLecturerRatingChange(lecturer.id, 'rating', e.target.value)}
                        className="form-control"
                        placeholder="1-5"
                        disabled={loading.lecturers}
                      />
                    </div>
                    <div className="col-md-6">
                      <input
                        type="text"
                        placeholder="Optional comment"
                        value={lecturerRatings[lecturer.id]?.comment || ''}
                        onChange={(e) => handleLecturerRatingChange(lecturer.id, 'comment', e.target.value)}
                        className="form-control"
                        disabled={loading.lecturers}
                      />
                    </div>
                    <div className="col-md-3">
                      <button
                        onClick={() => submitLecturerRating(lecturer.id)}
                        className="btn btn-warning w-100"
                        disabled={loading.lecturers || !lecturerRatings[lecturer.id]?.rating}
                      >
                        Submit
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="text-center text-muted py-4">
              <i className="fas fa-users fa-2x mb-2"></i>
              <p>No lecturers available to rate</p>
              <small>Enroll in classes to see your lecturers</small>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default StudentDashboard;
