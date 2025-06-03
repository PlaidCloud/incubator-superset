/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import PropTypes from 'prop-types';
import columnType from './columnType';
import AdhocMetricOption from './AdhocMetricOption';
import AdhocMetric from './AdhocMetric';
import savedMetricType from './savedMetricType';

const propTypes = {
  option: PropTypes.oneOfType([PropTypes.object, PropTypes.string]).isRequired,
  index: PropTypes.number.isRequired,
  onMetricEdit: PropTypes.func,
  onRemoveMetric: PropTypes.func,
  onMoveLabel: PropTypes.func,
  onDropLabel: PropTypes.func,
  columns: PropTypes.arrayOf(columnType),
  savedMetrics: PropTypes.arrayOf(savedMetricType),
  savedMetricsOptions: PropTypes.arrayOf(savedMetricType),
  multi: PropTypes.bool,
  datasource: PropTypes.object,
  datasourceWarningMessage: PropTypes.string,
};

export default function MetricDefinitionValue({
  option,
  onMetricEdit,
  onRemoveMetric,
  columns,
  savedMetrics,
  savedMetricsOptions,
  datasource,
  onMoveLabel,
  onDropLabel,
  index,
  type,
  multi,
  datasourceWarningMessage,
}) {
  const getSavedMetricByName = metricName =>
    savedMetrics.find(metric => metric.metric_name === metricName);

  let savedMetric;
  let isPlainObjectRepresentingAdhocOrHeading = false;

  if (typeof option === 'string') {
    // Option is a string, so it's a name of a saved metric
    savedMetric = getSavedMetricByName(option);
  } else if (typeof option === 'object' && option !== null) {
    // Option is an object
    if (option.metric_name) {
      // It has a metric_name, so it represents a saved metric
      savedMetric = option; // Assuming 'option' itself is the saved metric data
    } else if (
      // Check if it's a plain object representing an ad-hoc metric or heading
      // (i.e., not an AdhocMetric instance but has defining ad-hoc properties)
      !(option instanceof AdhocMetric) &&
      (option.emptyRowHeading === true)
    ) {
      isPlainObjectRepresentingAdhocOrHeading = true;
    }
  }

  if (option instanceof AdhocMetric || savedMetric || isPlainObjectRepresentingAdhocOrHeading) {
    let adhocMetricForChild; // This will be the AdhocMetric instance passed to AdhocMetricOption

    if (option instanceof AdhocMetric) {
      adhocMetricForChild = option;
    } else if (isPlainObjectRepresentingAdhocOrHeading) {
      const metricInitObject = { ...option };
      if (option.emptyRowHeading === true && typeof option.emptyRowHeadingText === 'string') {
        metricInitObject.label = option.emptyRowHeadingText;
        metricInitObject.hasCustomLabel = true;
      }
      adhocMetricForChild = new AdhocMetric(metricInitObject);
    } else {
      // Otherwise, it must be a saved metric (resolvedSavedMetric is true).
      // Create an AdhocMetric instance based on the saved metric data.
      // (The AdhocMetric constructor can take saved metric fields)
      adhocMetricForChild = new AdhocMetric(savedMetric || {});
    }

    const metricOptionProps = {
      onMetricEdit,
      onRemoveMetric,
      columns,
      savedMetricsOptions,
      datasource,
      adhocMetric: adhocMetricForChild,
      onMoveLabel,
      onDropLabel,
      index,
      savedMetric: savedMetric ?? {},
      type,
      multi,
      datasourceWarningMessage,
    };

    return <AdhocMetricOption {...metricOptionProps} />;
  }
  return null;
}
MetricDefinitionValue.propTypes = propTypes;
