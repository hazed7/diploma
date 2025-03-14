import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from "@nestjs/common";
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

export interface Response<T> {
	data: T;
	meta?: Record<string, any>;
}

@Injectable()
export class TransformInterceptor<T>
	implements NestInterceptor<T, Response<T>> {

	intercept(
		context: ExecutionContext,
		next: CallHandler,
	): Observable<Response<T>> {
		return next.handle().pipe(
			map((data) => {
				if (data && data.data !== undefined) {
					return data;
				}

				return {
					data,
					meta: {
						timestamp: new Date().toISOString(),
					},
				};
			}),
		);
	}
}
