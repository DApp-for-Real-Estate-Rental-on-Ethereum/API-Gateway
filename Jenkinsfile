pipeline {
    agent any

    environment {
        DOCKER_IMAGE_NAME = 'medgm/real-estate-api-gateway'
    }

    stages {
        stage('Checkout') {
            steps {
                script {
                    sh 'git rev-parse --short HEAD'
                }
            }
        }

        stage('Verify Project Layout') {
            steps {
                script {
                    sh '''
                        echo "Verifying api-gateway repository layout..."
                        pwd
                        ls -la
                        if [ ! -f pom.xml ]; then
                            echo "ERROR: pom.xml not found!"
                            ls -la
                            exit 1
                        fi
                        echo "pom.xml found."
                        echo "Cleaning leftover build artifacts..."
                        rm -rf target .dc-data || true
                        ls -la
                    '''
                }
            }
        }

        stage('Build & Test') {
            steps {
                script {
                    sh '''
                        echo "Building Spring Boot API Gateway..."
                        ./mvnw -B clean compile test
                    '''
                }
            }
        }

        stage('Publish Test Results') {
            steps {
                junit testResults: 'target/surefire-reports/*.xml', allowEmptyResults: true
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    sh """
                        echo "Building Docker image for API Gateway..."
                        docker build -t ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} .
                        docker tag ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} ${DOCKER_IMAGE_NAME}:latest
                        GIT_COMMIT_SHORT=\$(git rev-parse --short HEAD)
                        docker tag ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} ${DOCKER_IMAGE_NAME}:\${GIT_COMMIT_SHORT}
                        echo "Docker images created:"
                        docker images | grep ${DOCKER_IMAGE_NAME}
                    """
                }
            }
        }

        stage('Push to Docker Hub') {
            steps {
                script {
                    withCredentials([usernamePassword(credentialsId: 'docker-registry-creds', usernameVariable: 'DOCKER_USERNAME', passwordVariable: 'DOCKER_PASSWORD')]) {
                        sh """
                            echo "Logging into Docker Hub..."
                            echo $DOCKER_PASSWORD | docker login -u $DOCKER_USERNAME --password-stdin

                            GIT_COMMIT_SHORT=\$(git rev-parse --short HEAD)
                            echo "Pushing images to Docker Hub..."
                            docker push ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER}
                            docker push ${DOCKER_IMAGE_NAME}:latest
                            docker push ${DOCKER_IMAGE_NAME}:\${GIT_COMMIT_SHORT}
                        """
                    }
                }
            }
        }

        stage('Deploy to Local Registry') {
            steps {
                script {
                    sh """
                        echo "Tagging and pushing to local registry..."
                        docker tag ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} localhost:5000/real-estate-api-gateway:${BUILD_NUMBER}
                        docker tag ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} localhost:5000/real-estate-api-gateway:latest

                        docker push localhost:5000/real-estate-api-gateway:${BUILD_NUMBER}
                        docker push localhost:5000/real-estate-api-gateway:latest

                        echo "Images in local registry:"
                        docker images | grep real-estate-api-gateway
                    """
                }
            }
        }

        stage('Integration Tests') {
            steps {
                script {
                    sh '''
                        echo "Integration tests stage - placeholder"
                        echo "Extend with contract/integration tests when available."
                    '''
                }
            }
        }
    }

    post {
        always {
            script {
                sh """
                    echo "Cleaning up local Docker tags..."
                    docker rmi ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} || true
                    docker rmi ${DOCKER_IMAGE_NAME}:latest || true
                    docker rmi localhost:5000/real-estate-api-gateway:${BUILD_NUMBER} || true
                """
            }
        }
        success {
            echo "API Gateway pipeline completed successfully! 🎉"
        }
        failure {
            echo "API Gateway pipeline failed. ❌"
        }
    }
}

