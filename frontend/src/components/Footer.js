import React from 'react';
import '../App.css';

const Footer = () => {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="limkokwing-footer">
      <div className="footer-content">
        {/* Bottom Footer */}
        <div className="footer-bottom">
          <div className="footer-bottom-content">
            <div className="copyright">
              <p>&copy; {currentYear} Limkokwing University of Creative Technology. All rights reserved.</p>
            </div>
           
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;