# Rails routes fixture (source only). Not run.
Rails.application.routes.draw do
  resources :orders, only: [:show]
  get '/api/search', to: 'orders#search'
  namespace :admin do
    patch '/orders/:id/ship', to: 'orders#ship'
  end
end
