import { apiService } from '../api';

describe('API Service', () => {
  test('has correct base URL', () => {
    expect(apiService).toBeDefined();
  });

  test('exports required methods', () => {
    expect(typeof apiService.getSubscriptions).toBe('function');
    expect(typeof apiService.startScan).toBe('function');
    expect(typeof apiService.getScanStatus).toBe('function');
    expect(typeof apiService.getScanResult).toBe('function');
    expect(typeof apiService.listReports).toBe('function');
  });
});
