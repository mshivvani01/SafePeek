import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './styles/app.css';
import { applyTheme } from './utils/theme';

applyTheme();

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
