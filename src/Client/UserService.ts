import log from "loglevel";
import joinUrl from "url-join";
import { UserManager, UserManagerSettings } from "oidc-client";
import { distinctUntilChanged, pluck } from "rxjs/operators";
import { StateHandler, createStateHandler, StateProvider, set } from "@myCompany/state-management";
import { baseUrls } from "shared/utils/Urls";
import { asFactory, sameInstancePerSameArguments } from "shared/utils/FactoryHelpers";
import SignInProcess, { SignInProcessState, createSignInProcess } from "./SignInProcess";
import { createUser } from "./models/User";
import UserState, { defaultUserState } from "./state/UserState";

const openIdConnectConfig: UserManagerSettings = {
  authority: baseUrls.person,
  client_id: "js",
  redirect_uri: joinUrl(baseUrls.spa, "signincallback"),
  response_type: "code",
  scope: "openid offline_access profile Person.Api Translation.Api",
  post_logout_redirect_uri: baseUrls.spa,
  automaticSilentRenew: true
};

function withStateProvider<TState>(stateProvider: StateProvider<TState>) {
  return <TTarget extends {}>(target: TTarget) => ({
    ...target,
    get state() {
      return stateProvider.state;
    },
    state$: stateProvider.state$
  });
}

export function createInstance(
  userStateHandler: StateHandler<UserState>,
  userManager: UserManager,
  signInProcess: SignInProcess
) {
  function signIn() {
    return signInProcess
      .proceed()
      .then((state) => {
        if (state === SignInProcessState.Succeeded) {
          return signInProcess.getUser();
        }
      })
      .then((oidcUser) => {
        if (oidcUser !== undefined) {
          const token = {
            type: oidcUser.token_type,
            value: oidcUser.access_token
          };

          userStateHandler.setState(
            set(
              (state) => state.user,
              createUser({
                id: Number(oidcUser.profile.sub),
                firstName: oidcUser.profile.given_name || "no name",
                lastName: oidcUser.profile.family_name || "no name",
                token
              })
            )
          );
        }
      });
  }

  function forceSignIn() {
    resetUserToken();
    signInProcess.reset();
    userManager.clearStaleState();

    return signIn();
  }

  function signOut() {
    resetUserToken();

    return userManager.signoutRedirect();
  }

  function resetUserToken() {
    userStateHandler.setState(
      set(
        (state) => state.user,
        (currentUser) => createUser({ ...currentUser, token: undefined })
      )
    );
  }

  userManager.events.addSilentRenewError((error) => {
    log.error("Silent access token renewal error occured.", error);
  });

  userManager.events.addUserUnloaded(() => {
    log.error("User has been unloaded.");
  });

  userManager.events.addUserSignedOut(() => {
    log.info("User has signed out.");
  });

  userManager.events.addAccessTokenExpired(() => {
    log.error("Access token expired.");
    forceSignIn();
  });

  return withStateProvider(userStateHandler)({
    isSignedIn$: userStateHandler.state$.pipe(pluck("user", "isSignedIn"), distinctUntilChanged()),
    token$: userStateHandler.state$.pipe(pluck("user", "token"), distinctUntilChanged()),
    signIn,
    forceSignIn,
    signOut
  });
}

export const getUserService = asFactory(() => {
  const userManager = new UserManager(openIdConnectConfig);
  return createInstance(createStateHandler(defaultUserState), userManager, createSignInProcess(userManager));
}, sameInstancePerSameArguments());

type UserService = ReturnType<typeof createInstance>;

export default UserService;
