import axios from 'axios';
import { Request, Response, NextFunction } from 'express';
import unless from 'express-unless';
import { verify } from 'jsonwebtoken';
import { public_key } from './pub_key';

declare global {
  namespace Express {
    interface Request {
      ada_user: {
        [key: string]: any
      }
    }
  }
}

export type ADA_PARAMS = {
  fetchuser: true;
  token: string;
  app_id: string;
  scope?: string;
} | {
  fetchuser: false;
  token: string;
};

export type ADA_PARAMS_WITHOUT_TOKEN = {
  fetchuser: true;
  app_id: string;
  scope?: string;
} | {
  fetchuser: false;
};

const supported_version = '050';

export const validateFromEndpoint = async (
  scope: string | undefined,
  token: string,
  app_id: string,
) => {
  try {
    const url = scope
      ? `https://ada.cloud.piebits.org/${supported_version}/userops/fetch/self?scope=${scope}`
      : `https://ada.cloud.piebits.org/${supported_version}/userops/fetch/self`;

    const { data } = await axios.get<any>(
      url,
      {
        headers: {
          Authorization: token,
          'x-ada-app-id': app_id,
        },
      },
    );

    return data.user;
  } catch {
    throw new Error('Auth Token Invalid');
  }
};

export const validateToken = (token: string) => {
  try {
    if (token && token.startsWith('Bearer ')) {
      const sanitized_token = token.split('Bearer ')[1];

      const decoded = verify(sanitized_token, public_key, {
        issuer: 'https://ada.cloud.piebits.org',
        algorithms: ['RS256'],
      });

      return decoded as any;
    }
    throw new Error('Auth Token should start with bearer');
  } catch {
    throw new Error('Auth Token Invalid');
  }
};

export const validate = async (props: ADA_PARAMS) => {
  if (props.token) {
    if (props.fetchuser) {
      const data = await validateFromEndpoint(props.scope, props.token, props.app_id);

      return data;
    }
    const data = validateToken(props.token);

    return data;
  }

  throw new Error('Auth Token is required');
};

export const middleware = (props: ADA_PARAMS_WITHOUT_TOKEN): any => {
  const func = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = req.headers.authorization;

      if (!token) {
        res
          .status(401)
          .json({
            type: 'Auth Error',
            message: 'Auth Token Missing',
          });

        return;
      }
      const data = await validate({
        ...props,
        token,
      });

      req.ada_user = data;

      next();
    } catch (e: any) {
      res
        .status(401)
        .json({
          type: 'Auth Error',
          message: e.message,
        });
    }
  };

  func.unless = unless;

  return func;
};
