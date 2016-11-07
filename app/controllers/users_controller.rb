class UsersController < ApplicationController
  before_action :authenticate, except: [:login, :create]

  ####################################
  ##          /users routes         ##
  ####################################

  # GET /users
  def index
    users = User.all
    # cheer_ups = CheerUp.all
    render json: users
  end

  # POST /users
  def create
    user = User.new(user_params)
    if user.save
      render json: user, status: :created
    else
      render json: user.errors, status: :unprocessable_entity
    end
  end

  # POST /users/login
  def login
    user = User.find_by(username: params[:user][:username])

    if user && user.authenticate(params[:user][:password])
      token = token(user.id, user.username) # Added this
      render json: {status: 201, user: {id: user.id, username: user.username, cheer_ups: user.cheer_ups}, token: token}
    else
      render json: {status: 401, message: "unauthorized"}
    end
  end

  # GET /users/:id
  def show
    user = User.find(params[:id])
    user_cheer_ups = user.cheer_ups
    render json:
    {
      status: 200,
      user: user,
      user_cheer_ups: user_cheer_ups
    }
  end

  # PATCH/PUT /users/:id
  def update
    user = User.find(params[:id])
    if user.update(user_params)
      render json: user
    else
      render json: user.errors, status: :unprocessable_entity
    end
  end

  # DELETE /users/:id
  def destroy
    user = User.find(params[:id])
    user.destroy

    render json: {status: 204}
  end

  ####################################
  ##    /users/cheer_ups routes     ##
  ####################################

  # Adds a cheer_up to a user POST /users/:id/add_cheer_up
  def add_cheer_up
    new_cheer_up = current_user.cheer_ups.new(cheer_up_params)
    if new_cheer_up.save
      render json:
      {
        status: 200,
        user: current_user,
        cheer_up: current_user.cheer_ups
      }
    else
      render json:
      {
        status: 400,
        user: current_user,
        cheer_up: cheer_up.errors
      }
    end
  end

  # Updates a user's single cheer_up PATCH /users/:id/update_cheer_up
  def update_cheer_up
    user = User.find(params[:id])
    updating_cheer_up = CheerUp.find(params[:cheer_up_id])
    updating_cheer_up.update(cheer_up_params)
    render json:
    {
      status: 200,
      user: user,
      cheer_ups: user.cheer_ups,
      updated_cheer_up: updating_cheer_up
    } # end render json
  end

  # Remove a cheer_up from a user DELETE /users/:id/remove_cheer_up/:cheer_up_id
  def remove_cheer_up
    user = User.find(params[:id])
    cheer_up = CheerUp.find(params[:cheer_up_id])
    cheer_up.destroy
    render json:
    {
      status: 204,
      user: user,
      cheer_ups: user.cheer_ups,
      deleted_cheer_up: cheer_up
    } # end render json
  end

  private

    def token(id, username)
      JWT.encode(payload(id, username), ENV['JWT_SECRET'], 'HS256')
    end

    def payload(id, username)
      {
        exp: (Time.now + 1.day).to_i, # Expiration date 24 hours from now
        iat: Time.now.to_i,
        iss: ENV['JWT_ISSUER'],
        user: {
          id: id,
          username: username
        }
      }
    end

    def user_params
      params.require(:user).permit(:last_name, :first_name, :username, :password, :email)
    end

    def cheer_up_params
        params.require(:cheer_up).permit(:title, :content, :category, :user_id)
    end
end
