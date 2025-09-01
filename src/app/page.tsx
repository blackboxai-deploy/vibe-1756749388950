"use client"

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface XSSAlert {
  id: string;
  timestamp: string;
  sourceIp: string;
  url: string;
  riskLevel: 'low' | 'medium' | 'high';
  patterns: number;
  status: 'active' | 'resolved';
}

interface DetectionStats {
  totalPackets: number;
  xssDetected: number;
  detectionRate: number;
  connectedSwitches: number;
  patternsLoaded: number;
}

export default function XSSMonitorDashboard() {
  const [alerts, setAlerts] = useState<XSSAlert[]>([]);
  const [stats, setStats] = useState<DetectionStats>({
    totalPackets: 0,
    xssDetected: 0,
    detectionRate: 0,
    connectedSwitches: 0,
    patternsLoaded: 25
  });
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  // Simulate real-time data updates
  useEffect(() => {
    const interval = setInterval(() => {
      // Simulate new stats
      setStats(prev => ({
        ...prev,
        totalPackets: prev.totalPackets + Math.floor(Math.random() * 10) + 1,
        xssDetected: Math.random() > 0.95 ? prev.xssDetected + 1 : prev.xssDetected,
        detectionRate: prev.xssDetected > 0 ? (prev.xssDetected / prev.totalPackets) * 100 : 0,
        connectedSwitches: Math.floor(Math.random() * 3) + 1
      }));

      // Occasionally add new alerts
      if (Math.random() > 0.9) {
        const newAlert: XSSAlert = {
          id: `alert-${Date.now()}`,
          timestamp: new Date().toISOString(),
          sourceIp: `192.168.1.${Math.floor(Math.random() * 100) + 100}`,
          url: `/search?q=<script>alert('XSS')</script>`,
          riskLevel: ['low', 'medium', 'high'][Math.floor(Math.random() * 3)] as 'low' | 'medium' | 'high',
          patterns: Math.floor(Math.random() * 5) + 1,
          status: 'active'
        };
        setAlerts(prev => [newAlert, ...prev.slice(0, 9)]);
      }

      setLastUpdate(new Date());
    }, 2000);

    setIsConnected(true);
    return () => clearInterval(interval);
  }, []);

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'high': return 'bg-red-100 text-red-800 border-red-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-green-100 text-green-800 border-green-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const resolveAlert = (alertId: string) => {
    setAlerts(prev => 
      prev.map(alert => 
        alert.id === alertId 
          ? { ...alert, status: 'resolved' }
          : alert
      )
    );
  };

  const clearAllAlerts = () => {
    setAlerts([]);
  };

  return (
    <div className="min-h-screen bg-gray-50 p-4">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">XSS Attack Detection System</h1>
              <p className="text-gray-600 mt-1">Real-time IoT Security Monitoring Dashboard</p>
              <p className="text-sm text-gray-500">Bachelor's Final Year Project</p>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-400' : 'bg-red-400'}`}></div>
                <span className="text-sm text-gray-600">
                  {isConnected ? 'Connected to POX Controller' : 'Disconnected'}
                </span>
              </div>
              <Badge variant="outline" className="text-xs">
                Last update: {lastUpdate.toLocaleTimeString()}
              </Badge>
            </div>
          </div>
        </div>

        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-600">Total Packets</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">{stats.totalPackets.toLocaleString()}</div>
              <p className="text-xs text-gray-500 mt-1">Analyzed packets</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-600">XSS Detected</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{stats.xssDetected}</div>
              <p className="text-xs text-gray-500 mt-1">Attack attempts</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-600">Detection Rate</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-yellow-600">{stats.detectionRate.toFixed(2)}%</div>
              <p className="text-xs text-gray-500 mt-1">Attack percentage</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-600">Active Switches</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{stats.connectedSwitches}</div>
              <p className="text-xs text-gray-500 mt-1">Network switches</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-600">Patterns Loaded</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-purple-600">{stats.patternsLoaded}</div>
              <p className="text-xs text-gray-500 mt-1">Detection rules</p>
            </CardContent>
          </Card>
        </div>

        {/* Real-time Alerts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Active Alerts */}
          <Card className="h-fit">
            <CardHeader className="pb-4">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg">Active Security Alerts</CardTitle>
                  <CardDescription>Real-time XSS attack detections</CardDescription>
                </div>
                {alerts.filter(a => a.status === 'active').length > 0 && (
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={clearAllAlerts}
                    className="text-xs"
                  >
                    Clear All
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4 max-h-96 overflow-y-auto">
                {alerts.filter(alert => alert.status === 'active').length === 0 ? (
                  <div className="text-center py-8 text-gray-500">
                    <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-green-100 flex items-center justify-center">
                      <div className="w-6 h-6 bg-green-500 rounded-full" />
                    </div>
                    <p>No active security threats detected</p>
                    <p className="text-sm text-gray-400">System is monitoring network traffic</p>
                  </div>
                ) : (
                  alerts
                    .filter(alert => alert.status === 'active')
                    .map((alert) => (
                      <Alert key={alert.id} className="border-l-4 border-l-red-500">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center space-x-2 mb-2">
                              <Badge className={getRiskColor(alert.riskLevel)}>
                                {alert.riskLevel.toUpperCase()} RISK
                              </Badge>
                              <span className="text-xs text-gray-500">
                                {new Date(alert.timestamp).toLocaleTimeString()}
                              </span>
                            </div>
                            <AlertDescription>
                              <div className="space-y-1">
                                <p><strong>Source:</strong> {alert.sourceIp}</p>
                                <p><strong>Target:</strong> {alert.url}</p>
                                <p><strong>Patterns:</strong> {alert.patterns} detected</p>
                              </div>
                            </AlertDescription>
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => resolveAlert(alert.id)}
                            className="text-xs h-6 px-2"
                          >
                            Resolve
                          </Button>
                        </div>
                      </Alert>
                    ))
                )}
              </div>
            </CardContent>
          </Card>

          {/* System Status */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">System Status</CardTitle>
              <CardDescription>POX Controller and Network Status</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                    <span className="text-sm font-medium">POX Controller</span>
                  </div>
                  <Badge variant="outline" className="bg-green-50 text-green-700">Running</Badge>
                </div>

                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                    <span className="text-sm font-medium">XSS Detection Engine</span>
                  </div>
                  <Badge variant="outline" className="bg-green-50 text-green-700">Active</Badge>
                </div>

                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                    <span className="text-sm font-medium">Network Monitoring</span>
                  </div>
                  <Badge variant="outline" className="bg-blue-50 text-blue-700">Monitoring</Badge>
                </div>

                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
                    <span className="text-sm font-medium">IoT Devices</span>
                  </div>
                  <Badge variant="outline" className="bg-yellow-50 text-yellow-700">
                    {stats.connectedSwitches * 2} Connected
                  </Badge>
                </div>
              </div>

              <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                <h4 className="text-sm font-medium text-blue-800 mb-2">Project Information</h4>
                <div className="text-xs text-blue-700 space-y-1">
                  <p>Bachelor's Final Year Project</p>
                  <p>XSS Attack Detection for IoT Devices</p>
                  <p>Using POX Controller & Mininet-WiFi</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Recent Resolved Alerts */}
        {alerts.filter(alert => alert.status === 'resolved').length > 0 && (
          <Card className="mt-8">
            <CardHeader>
              <CardTitle className="text-lg">Recently Resolved Alerts</CardTitle>
              <CardDescription>Previously detected and resolved security incidents</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {alerts
                  .filter(alert => alert.status === 'resolved')
                  .slice(0, 5)
                  .map((alert) => (
                    <div key={alert.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg opacity-60">
                      <div className="flex items-center space-x-3">
                        <div className="w-2 h-2 bg-gray-400 rounded-full"></div>
                        <div className="text-sm">
                          <span className="font-medium">{alert.sourceIp}</span>
                          <span className="text-gray-500 ml-2">→ {alert.url.substring(0, 50)}...</span>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge variant="outline" className="text-xs bg-gray-100">
                          {alert.riskLevel}
                        </Badge>
                        <span className="text-xs text-gray-500">
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}