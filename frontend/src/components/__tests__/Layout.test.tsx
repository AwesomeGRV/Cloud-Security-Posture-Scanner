import React from 'react';
import { screen } from '@testing-library/react';
import Layout from '../Layout';
import { render } from './test-utils';

describe('Layout Component', () => {
  test('renders without crashing', () => {
    expect(() => render(<Layout><div>Test Content</div></Layout>)).not.toThrow();
  });

  test('renders children correctly', () => {
    render(<Layout><div>Test Content</div></Layout>);
    expect(screen.getByText('Test Content')).toBeInTheDocument();
  });

  test('renders CSPM branding', () => {
    render(<Layout><div>Test Content</div></Layout>);
    expect(screen.getByText('CSPM')).toBeInTheDocument();
  });

  test('renders navigation', () => {
    render(<Layout><div>Test Content</div></Layout>);
    expect(screen.getByRole('navigation')).toBeInTheDocument();
  });
});
