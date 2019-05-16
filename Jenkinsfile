#!/usr/bin/env groovy

image_name = "plaidcloud/superset"

podTemplate(label: 'io',
  containers: [
    containerTemplate(name: 'docker', image: 'docker:18.09.5', ttyEnabled: true, command: 'cat'),
    containerTemplate(name: 'kubectl', image: "lachlanevenson/k8s-kubectl:v1.13.5", ttyEnabled: true, command: 'cat')
  ],
  volumes: [
    hostPathVolume(hostPath: '/var/run/docker.sock', mountPath: '/var/run/docker.sock')
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
    container('docker') {
      docker.withRegistry('', 'plaid-docker') {
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
        CHANGE_BRANCH = env.CHANGE_BRANCH ?: scm_map.GIT_BRANCH.minus(~/^origin\//)
        
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


        if (CHANGE_BRANCH == 'master' || params.deploy_to_kubernetes) {
          stage('Build Image') {
            image = docker.build("${image_name}:latest", "--pull ${docker_args} .")
          }

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
              sh "kubectl -n plaid set image deployment/superset superset=${image_name}:${image_label} --record"
            }
          }
        }
      }
    }
  }
}
