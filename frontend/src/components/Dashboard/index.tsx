import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Grid,
  Card,
  CardContent,
  CardActions,
  Typography,
  Button,
  Box,
  CardActionArea,
} from '@mui/material';
import { styled } from '@mui/material/styles';
import SecurityIcon from '@mui/icons-material/Security';
import BugReportIcon from '@mui/icons-material/BugReport';
import StorageIcon from '@mui/icons-material/Storage';
import CodeIcon from '@mui/icons-material/Code';
import SearchIcon from '@mui/icons-material/Search';
import WifiIcon from '@mui/icons-material/Wifi';
import VirusIcon from '@mui/icons-material/Coronavirus';

const StyledCard = styled(Card)(({ theme }) => ({
  height: '100%',
  display: 'flex',
  flexDirection: 'column',
  transition: 'transform 0.2s ease-in-out',
  '&:hover': {
    transform: 'translateY(-5px)',
  },
}));

const IconWrapper = styled(Box)(({ theme }) => ({
  display: 'flex',
  justifyContent: 'center',
  marginBottom: theme.spacing(2),
  '& > svg': {
    fontSize: 48,
    color: theme.palette.primary.main,
  },
}));

const tools = [
  {
    title: 'Malware Analysis',
    description: 'Analyze suspicious files with Binwalk and ClamAV',
    icon: VirusIcon,
    route: '/malware-analysis'
  },
  {
    title: 'Network Scanning',
    description: 'Scan and enumerate network targets',
    icon: SearchIcon,
    route: '/network'
  },
  {
    title: 'Web Security',
    description: 'Test web applications for vulnerabilities',
    icon: SecurityIcon,
    route: '/web'
  },
  {
    title: 'Exploitation',
    description: 'Exploit known vulnerabilities',
    icon: BugReportIcon,
    route: '/exploit'
  },
  {
    title: 'Database',
    description: 'Test database security',
    icon: StorageIcon,
    route: '/database'
  },
  {
    title: 'Wireless',
    description: 'Test wireless network security',
    icon: WifiIcon,
    route: '/wireless'
  },
  {
    title: 'Code Analysis',
    description: 'Analyze source code for vulnerabilities',
    icon: CodeIcon,
    route: '/code'
  }
];

const Dashboard = () => {
  const navigate = useNavigate();

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        Toolbox Newgen
      </Typography>
      <Grid container spacing={3}>
        {tools.map((tool, index) => (
          <Grid item xs={12} sm={6} md={4} key={index}>
            <Card>
              <CardActionArea onClick={() => navigate(tool.route)}>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <tool.icon fontSize="large" color="primary" />
                    <Typography variant="h6" component="div" sx={{ ml: 1 }}>
                      {tool.title}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {tool.description}
                  </Typography>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Container>
  );
};

export default Dashboard; 