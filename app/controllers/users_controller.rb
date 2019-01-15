class UsersController < ApplicationController
  before_action :logged_in_user, only: %i(edit update)
  before_action :correct_user, only: %i(edit update)
  before_action :admin_user, only: :destroy

  def index
    @users = User.page(params[:page]).per Settings.split
  end
  
  def new
    @user = User.new
  end

  def create
    @user = User.new user_params

    if @user.save
      log_in @user
      flash[:success] = t ".sample_app"
      redirect_to @user
    else
      flash[:danger] = t ".signup_err"
      render :new
    end
  end

  def show
    @user = User.find_by id: params[:id]

    return if @user
    flash[:danger] = t "notice_show"
    redirect_to signup_path
  end

  def edit; end

  def update
    @user = User.find params[:id]

    if @user.update_attributes user_params
      flash[:success] = t "updated"
      redirect_to @user
    else
      flash[:danger] = t "notice_show"
      render "edit"
   end
  end

  def destroy
    if User.find(params[:id]).destroy
      flash[:success] = t "deleted"
      redirect_to users_url
    else
      flash[:success] = t "cantdelete"
      render :users
    end
  end

  private

  def user_params
    params.require(:user).permit :name, :email, :password,
      :password_confirmation
  end

  def correct_user
    @user = User.find params[:id]
    redirect_to(root_url) unless @user == current_user
  end

  def logged_in_user
    return false if logged_in?
      store_location
      flash[:danger] = t ".plslogin"
      redirect_to login_url
    end
  end

  def admin_user
    redirect_to(root_url) unless current_user.admin?
  end
