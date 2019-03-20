#!/usr/bin/env groovy

plaid_image = "plaidcloud/superset"

podTemplate(label: 'io',
  containers: [
    containerTemplate(name: 'docker', image: 'docker:18.09.3-git', ttyEnabled: true, command: 'cat'),
    containerTemplate(name: 'kubectl', image: "lachlanevenson/k8s-kubectl:v1.11.3", ttyEnabled: true, command: 'cat')
  ],
  serviceAccount: 'jenkins'
)
{
  node(label: 'io') {
    properties([
      parameters([
        booleanParam(name: 'no_cache', defaultValue: false, description: 'Adds --no-cache flag to docker build command(s).'),
        booleanParam(name: 'deploy_to_kubernetes', defaultValue: false, description: 'Force Jenkins to run the "Deploy to Kubernetes" stage')
      ])
    ])
    withCredentials([string(credentialsId: 'offsite-host', variable: 'host')]) {
      container('docker') {
        docker.withServer("$host", 'remote-docker-credentials') {
          docker.withRegistry('', 'gbates101') {

            // Checkout source before doing anything else
            scm_map = checkout([
                $class: 'GitSCM',
                branches: scm.branches,
                doGenerateSubmoduleConfigurations: false,
                extensions: [[$class: 'SubmoduleOption', disableSubmodules: false, parentCredentials: true, recursiveSubmodules: false, reference: '', trackingSubmodules: false]],
                submoduleCfg: [],
                userRemoteConfigs: scm.userRemoteConfigs //[[credentialsId: 'plaid-machine-user', url: 'https://github.com/PlaidCloud/incubator-superset/']]
            ])

            // Params are always strings. Convert to the type we want.
            docker_flags = ''
            if (no_cache.toBoolean()) {
              docker_flags += '--no-cache'
            }

            // TODO: Rework this to lint via tox commands provided by superset.
            // stage('Run Linter') {
            //   if (scm_map.GIT_BRANCH == 'master') {
            //     docker.build("${plaid_image}:lint", "--pull --target=lint${docker_flags}.").withRun('-t', 'pylint_runner') {c ->
            //       sh "docker logs ${c.id}>pylint.log"
            //     }
            //     recordIssues tool: pyLint(pattern: 'pylint.log')
            //   } else {
            //     docker.build("${plaid_image}:lint", "--pull --target=lint${docker_flags}.").withRun('-t') {c ->
            //       sh "docker logs ${c.id}>pylint.log"
            //     }
            //     recordIssues tool: pyLint(pattern: 'pylint.log'), qualityGates: [[threshold: 1, type: 'TOTAL_HIGH', unstable: true]]
            //   }
            // }

            stage('Build Image') {
              image = docker.build("${plaid_image}:latest", "--pull ${docker_flags} .")
            }

            if (scm_map.GIT_BRANCH == 'master' || deploy_to_kubernetes) {

              stage('Publish to DockerHub') {
                image.push()
              }

              stage('Publish Commit Tag') {
                // Add additional, unique image tag and push.
                // https://github.com/jenkinsci/docker-workflow-plugin/blob/50ad50bad2ee14eb73d1ae3ef1058b8ad76c9e5d/src/main/resources/org/jenkinsci/plugins/docker/workflow/Docker.groovy#L176-L179
                image_label = scm_map.GIT_COMMIT.substring(0, 7)
                image.push(image_label)
              }

              stage("Deploy to Kubernetes") {
                container('kubectl') {
                  sh "kubectl -n plaid set image deployment/superset superset=plaidcloud/superset:${image_label} --record"
                }
              }
            }
          }
        }
      }
    }
  }
}
