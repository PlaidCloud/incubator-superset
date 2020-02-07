#!/usr/bin/env groovy
import groovy.transform.Field

@Field 
def image_name = "plaidcloud/superset"

@Field
def image_label = ""

@Field
def branch = ""

podTemplate(label: 'superset',
  containers: [
    containerTemplate(name: 'docker', image: 'docker:18.09.9', ttyEnabled: true, command: 'cat'),
    containerTemplate(name: 'kubectl', image: "lachlanevenson/k8s-kubectl:v1.15.9", ttyEnabled: true, command: 'cat')
  ],
  serviceAccount: 'jenkins'
)
{
  node(label: 'superset') {
    properties([
      parameters([
        booleanParam(name: 'no_cache', defaultValue: false, description: 'Adds --no-cache flag to docker build command(s).'),
        booleanParam(name: 'deploy_to_kubernetes', defaultValue: false, description: 'Force Jenkins to run the "Deploy to Kubernetes" stage')
      ])
    ]) 
    container('docker') {
      withCredentials([string(credentialsId: 'docker-server-ip', variable: 'host')]) {
        docker.withServer("$host", "docker-server") {
          withCredentials([dockerCert(credentialsId: 'docker-server', variable: "DOCKER_CERT_PATH")]) {
            docker.withRegistry("", "plaid-docker") {
              // Checkout source before doing anything else
              scm_map = checkout([
                  $class: 'GitSCM',
                  branches: scm.branches,
                  doGenerateSubmoduleConfigurations: false,
                  extensions: [[$class: 'SubmoduleOption', disableSubmodules: false, parentCredentials: true, recursiveSubmodules: true, reference: '', trackingSubmodules: true]],
                  submoduleCfg: [],
                  userRemoteConfigs: scm.userRemoteConfigs //[[credentialsId: 'plaid-machine-user', url: 'https://github.com/PlaidCloud/incubator-superset/']]
              ])

              // When building from a PR event, we want to read the branch name from the CHANGE_BRANCH binding. This binding does not exist on branch events.
              branch = env.CHANGE_BRANCH ?: scm_map.GIT_BRANCH.minus(~/^origin\//)
              
              docker_args = ''

              // Add any extra docker build arguments here.
              if (params.no_cache) {
                docker_args += '--no-cache'
              }

              // TODO: Rework this to lint via tox commands provided by superset.
              // stage('Run Linter') {
              //   if (CHANGE_BRANCH == 'master') {
              //     docker.build("${image_name}:lint", "--pull --target=lint ${docker_args} .").withRun('-t', 'pylint_runner') {c ->
              //       sh """
              //         docker wait ${c.id}
              //         docker cp ${c.id}:/home/superset/pylint.log pylint.log
              //       """
              //     }
              //     recordIssues tool: pyLint(pattern: 'pylint.log')
              //   } else {
              //     docker.build("${image_name}:lint", "--pull --target=lint ${docker_args} .").withRun('-t') {c ->
              //       sh """
              //         docker wait ${c.id}
              //         docker cp ${c.id}:/home/superset/pylint.log pylint.log
              //       """
              //     }
              //     recordIssues tool: pyLint(pattern: 'pylint.log'), qualityGates: [[threshold: 1, type: 'TOTAL_HIGH', unstable: true]]
              //   }
              // }


              if (branch == 'develop' || params.deploy_to_kubernetes) {
                stage('Build Image') {
                  python_version="3.6.9"
                  sh "docker pull python:${python_version}"
                  image = docker.build("${image_name}:latest", "--build-arg PY_VER=${python_version} --pull ${docker_args} --target lean .")
                  events_image = docker.build("${image_name}-events:latest", "--build-arg PY_VER=${python_version} --pull ${docker_args} -f Dockerfile.events .")
                }

                stage('Publish to DockerHub') {
                  image.push()
                  events_image.push()
                }

                stage('Publish Commit Tag') {
                  // Add additional, unique image tag and push.
                  // https://github.com/jenkinsci/docker-workflow-plugin/blob/50ad50bad2ee14eb73d1ae3ef1058b8ad76c9e5d/src/main/resources/org/jenkinsci/plugins/docker/workflow/Docker.groovy#L176-L179
                  image_label = "${scm_map.GIT_COMMIT.substring(0, 7)}-${BUILD_NUMBER}"
                  image.push(image_label)
                  events_image.push(image_label)
                }
              }
            }
          }
        }
      }
    }
    if (branch == 'develop' || params.deploy_to_kubernetes) {
      container('kubectl') {
        stage("Deploy superset to Kubernetes") {
          sh "kubectl -n plaid set image deployment/superset superset=${image_name}:${image_label} --record"
        }
        stage("Deploy superset-events to Kubernetes") {
          sh "kubectl -n plaid set image deployment/superset-events superset=${image_name}-events:${image_label} --record"
        }
      }
    }
  }
}
