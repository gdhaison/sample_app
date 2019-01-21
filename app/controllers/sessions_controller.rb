class SessionsController < ApplicationController
  def new; end

  def create
    user = User.find_by email: params[:session][:email].downcase

    if user&.authenticate params[:session][:password]
      log_in user
      remember user
      redirect_to user
      flash[:succcess] = t "success"
    else
      flash[:danger] = t "invalid_pass"
      render :new
    end
  end

  def destroy
    log_out if logged_in?
    redirect_to root_url
  end

  def remember_login user
    log_in user
    rmb = params[:session][:remember_me]
    rmb == Settings.remember_me ? remember(user) : forget(user)
    redirect_back_or user
  end
end
