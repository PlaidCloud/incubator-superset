module.exports = {
  moduleNameMapper: {
    '^@superset-ui/chart-controls$':
      '<rootDir>/test/__mocks__/supersetUiChartControls.js',
    '^@superset-ui/core$': '<rootDir>/test/__mocks__/supersetUiCore.js',
    '\\.(png|jpg|gif)$': '<rootDir>/test/__mocks__/mockExportString.js',
  },
  testEnvironment: 'jsdom',
  transform: {
    '^.+\\.(ts|tsx|js|jsx)$': 'babel-jest',
  },
};
