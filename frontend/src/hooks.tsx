import { useDispatch, useSelector } from 'react-redux'
import type { RootState, AppDispatch } from './store'

// Používaj tieto hooky v celej aplikácii namiesto obyčajných
export const useAppDispatch = useDispatch.withTypes<AppDispatch>()
export const useAppSelector = useSelector.withTypes<RootState>()