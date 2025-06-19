import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Dashboard from './components/Dashboard';
import Layout from './components/Layout';
import MalwareAnalyzer from './components/MalwareAnalysis/MalwareAnalyzer';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
  },
});

function App() {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Router>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/malware-analysis" element={<MalwareAnalyzer />} />
            {/* Autres routes à ajouter ici */}
          </Routes>
        </Layout>
      </Router>
    </ThemeProvider>
  );
}

export default App; 