/**
 * Mock Data Generator for Whale Curve Analysis
 * Creates 1000 customer records with various metrics that demonstrate different
 * distribution patterns for whale chart visualization.
 */

export interface WhaleChartDataRecord {
  customerName: string;
  revenue: number;
  profit: number;
  orderCount: number;
  marketingCost: number;
  customerLifetime: number;
  returnRate: number;
}

/**
 * Generates realistic mock data for a whale curve chart with 1000 entries
 * - Revenue: Classic whale curve distribution
 * - Profit: True whale-shaped curve with negative values for least profitable customers
 * - OrderCount: Somewhat correlated with revenue but with variations
 * - MarketingCost: U-shaped distribution (good for secondary axis)
 * - CustomerLifetime: Inverse relationship to revenue
 * - ReturnRate: Higher for smaller customers
 */
export function generateWhaleData(numRecords = 1000): WhaleChartDataRecord[] {
  const data: WhaleChartDataRecord[] = [];

  // Company name components for random generation
  const prefixes = [
    'Global',
    'Metro',
    'Alpha',
    'Prime',
    'Eco',
    'Tech',
    'Mega',
    'Micro',
    'First',
    'Smart',
  ];
  const suffixes = [
    'Corp',
    'Inc',
    'LLC',
    'Group',
    'Partners',
    'Solutions',
    'Industries',
    'Systems',
    'Enterprises',
    'Networks',
  ];
  const middles = [
    'Tech',
    'Trade',
    'Retail',
    'Logistics',
    'Pharma',
    'Foods',
    'Media',
    'Finance',
    'Energy',
    'Services',
  ];

  // Generate the data with carefully crafted distributions
  for (let i = 0; i < numRecords; i += 1) {
    // Generate customer name
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
    const middle = middles[Math.floor(Math.random() * middles.length)];
    const suffix = suffixes[Math.floor(Math.random() * suffixes.length)];
    const customerName = `${prefix} ${middle} ${suffix}`;

    // Create exponential distribution for revenue - classic whale curve
    // Small number of high-value customers, many low-value customers
    const percentile = i / numRecords;
    const revenueBase = Math.pow(1 - percentile, 3) * 1000000; // Exponential curve
    const revenue = revenueBase * (0.8 + Math.random() * 0.4); // Add some noise

    // Profit follows revenue but with variations - true whale curve
    // Top customers are very profitable, middle customers break even, bottom customers may be unprofitable
    let profitMargin;

    if (percentile < 0.2) {
      // Top 20% - high margin (20-40%)
      profitMargin = 0.2 + Math.random() * 0.2;
    } else if (percentile < 0.5) {
      // Next 30% - moderate margin (10-20%)
      profitMargin = 0.1 + Math.random() * 0.1;
    } else if (percentile < 0.8) {
      // Next 30% - low margin (0-10%)
      profitMargin = Math.random() * 0.1;
    } else {
      // Bottom 20% - possibly negative margin (-10% to 5%)
      profitMargin = -0.1 + Math.random() * 0.15;
    }

    const profit = revenue * profitMargin;

    // Order count - somewhat correlated with revenue but not perfectly
    const orderCount = Math.round((revenue / 5000) * (0.5 + Math.random()));

    // Marketing cost - higher for top and bottom customers, creating a "U" shape
    // when plotted on secondary axis
    let marketingRate;
    if (percentile < 0.1 || percentile > 0.9) {
      // High marketing spend on very top and very bottom customers
      marketingRate = 0.1 + Math.random() * 0.15;
    } else {
      // Lower marketing spend on middle customers
      marketingRate = 0.03 + Math.random() * 0.07;
    }
    const marketingCost = revenue * marketingRate;

    // Customer lifetime in years - somewhat inverse to revenue
    // Smaller customers tend to have been around longer
    const customerLifetime = Math.max(
      1,
      Math.round(
        (10 - 8 * Math.pow(1 - percentile, 2)) * (0.7 + Math.random() * 0.6),
      ),
    );

    // Return rate - somewhat random but higher for smaller customers
    const returnRate = Math.min(
      50,
      Math.max(0, percentile * 25 * (0.5 + Math.random())),
    );

    data.push({
      customerName,
      revenue: Math.round(revenue),
      profit: Math.round(profit),
      orderCount,
      marketingCost: Math.round(marketingCost),
      customerLifetime,
      returnRate,
    });
  }

  // Sort by revenue descending to see the whale curve effect
  return data.sort((a, b) => b.revenue - a.revenue);
}

/**
 * Pre-generated mock data with 1000 records
 */
export const whaleChartMockData = generateWhaleData(1000);

/**
 * Generates analytics about the mock data's distribution
 * Shows how the top percentages of customers contribute to overall metrics
 */
export function getDistributionAnalytics() {
  const totalRevenue = whaleChartMockData.reduce(
    (sum, record) => sum + record.revenue,
    0,
  );
  const totalProfit = whaleChartMockData.reduce(
    (sum, record) => sum + record.profit,
    0,
  );

  const analytics = {
    totalRecords: whaleChartMockData.length,
    totalRevenue,
    totalProfit,
    distribution: {} as Record<string, { revenue: number; profit: number }>,
  };

  [10, 20, 50, 80].forEach(percentile => {
    const recordCount = Math.floor(
      whaleChartMockData.length * (percentile / 100),
    );
    const recordsSlice = whaleChartMockData.slice(0, recordCount);

    const sliceRevenue = recordsSlice.reduce(
      (sum, record) => sum + record.revenue,
      0,
    );
    const sliceProfit = recordsSlice.reduce(
      (sum, record) => sum + record.profit,
      0,
    );

    analytics.distribution[`top${percentile}Percent`] = {
      revenue: parseFloat(((sliceRevenue / totalRevenue) * 100).toFixed(1)),
      profit: parseFloat(((sliceProfit / totalProfit) * 100).toFixed(1)),
    };
  });

  return analytics;
}

/**
 * Converts the mock data to CSV format
 * @returns CSV string representation of the whale chart data
 */
export function convertToCSV(data: WhaleChartDataRecord[] = whaleChartMockData): string {
  // Define the headers
  const headers = [
    'customerName',
    'revenue',
    'profit',
    'orderCount',
    'marketingCost',
    'customerLifetime',
    'returnRate'
  ];
  
  // Create the header row
  let csvContent = headers.join(',') + '\n';
  
  // Add each data row
  data.forEach(record => {
    const row = [
      `"${record.customerName}"`, // Quoted to handle commas in names
      record.revenue,
      record.profit,
      record.orderCount,
      record.marketingCost,
      record.customerLifetime,
      record.returnRate
    ];
    csvContent += row.join(',') + '\n';
  });
  
  return csvContent;
}

// Example of analytics output for verification
// console.log(getDistributionAnalytics());
